#!/usr/bin/env python3
"""
sbom_validator.py — CHARLOTTE Supply-Chain: CycloneDX SBOM validation (OSV/NVD)

Capabilities
-----------
1) Load CycloneDX JSON SBOM
2) Normalize components (purl or name+version)
3) Query OSV batch API (fast, free) for known vulns
4) Optionally query NVD CVE 2.0 API (requires NVD API key or low-rate unauth)
5) Basic license-policy checks (deny/allow lists)
6) Output structured findings; emit CSV/JSON reports
7) CHARLOTTE plugin entrypoints: run(), run_plugin(config)

Environment (optional)
----------------------
- NVD_API_KEY            : NVD 2.0 API key (https://nvd.nist.gov/developers/request-an-api-key)
- HTTP_PROXY / HTTPS_PROXY: Standard proxy envs
- SBOM_VALIDATOR_TIMEOUT : HTTP timeout seconds (default 15)
- SBOM_VALIDATOR_OSV_URL : Override OSV API URL (default https://api.osv.dev/v1/querybatch)
- SBOM_VALIDATOR_NVD_URL : Override NVD API base (default https://services.nvd.nist.gov/rest/json/cves/2.0)

CLI
---
python sbom_validator.py --sbom path/to/sbom.json --out-json findings.json --out-csv findings.csv --use-nvd
"""

from __future__ import annotations

import argparse
import csv
import dataclasses
import json
import os
import re
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from collections.abc import Iterable

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # helpful error later

# ──────────────────────────────────────────────────────────────────────────────
# Datamodels
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class Component:
    id: str  # stable key (prefer PURL)
    name: str
    version: str
    purl: str | None = None
    licenses: list[str] = dataclasses.field(default_factory=list)
    hashes: dict[str, str] = dataclasses.field(
        default_factory=dict
    )  # e.g., {"SHA-256": "..."}
    ecosystem: str | None = None  # derived from purl if possible
    qualifiers: dict[str, str] = dataclasses.field(default_factory=dict)


@dataclass
class VulnerabilityRef:
    source: str  # "OSV" | "NVD"
    id: str  # e.g., CVE-2023-1234 / GHSA-... / OSV-...
    severity: str | None = None  # e.g., CRITICAL/HIGH/MED/LOW/UNKNOWN
    cvss_score: float | None = None
    summary: str | None = None
    url: str | None = None


@dataclass
class Finding:
    component_id: str
    name: str
    version: str
    purl: str | None
    issues: list[VulnerabilityRef] = dataclasses.field(default_factory=list)
    license_flags: list[str] = dataclasses.field(
        default_factory=list
    )  # reasons if failed policy
    notes: list[str] = dataclasses.field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

_PURL_ECOSYSTEM_MAP = {
    # purl spec: pkg:<type>/<name>@<version>?qualifiers
    # https://github.com/package-url/purl-spec
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "golang": "Go",
    "cargo": "Crates",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "apk": "Alpine",
    "deb": "Debian",
    "rpm": "RPM",
    "github": "GitHub",
}

SEVERITY_ORDER = [
    "CRITICAL",
    "HIGH",
    "MODERATE",
    "MEDIUM",
    "LOW",
    "UNKNOWN",
]  # we'll normalize into these buckets


def _norm_severity(label: str | None, score: float | None) -> str:
    """
    Normalize heterogeneous severity inputs into our buckets.
    Prefer label if given; otherwise bucket by score.
    """
    if label:
        up = label.upper()
        # map common variants
        aliases = {
            "MODERATE": "MODERATE",
            "MEDIUM": "MEDIUM",
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "LOW": "LOW",
        }
        if up in aliases:
            return aliases[up]
        if up in ("UNKNOWN", "NONE"):
            return "UNKNOWN"
    if score is not None:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0:
            return "LOW"
    return "UNKNOWN"


def _extract_licenses(cdx_comp: dict[str, Any]) -> list[str]:
    out = []
    # CycloneDX components[].licenses[].license.id OR .name
    for lic in cdx_comp.get("licenses", []) or []:
        lic_obj = lic.get("license") or {}
        if "id" in lic_obj:
            out.append(str(lic_obj["id"]))
        elif "name" in lic_obj:
            out.append(str(lic_obj["name"]))
    # Some SBOMs include "license" at top-level
    if not out and cdx_comp.get("license"):
        out.append(str(cdx_comp["license"]))
    return list(dict.fromkeys(out))  # dedupe preserve order


def _parse_purl(purl: str) -> tuple[str | None, dict[str, str]]:
    """
    Return (ecosystem, qualifiers) from purl.
    """
    try:
        m = re.match(r"^pkg:([^/]+)/([^@]+)@?([^?]+)?(?:\?(.*))?$", purl)
        if not m:
            return None, {}
        ptype = m.group(1)
        qualifiers = {}
        if m.group(4):
            for kv in m.group(4).split("&"):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    qualifiers[k] = v
        return _PURL_ECOSYSTEM_MAP.get(ptype, ptype), qualifiers
    except Exception:
        return None, {}


def _timeout() -> int:
    try:
        return int(os.getenv("SBOM_VALIDATOR_TIMEOUT", "15"))
    except Exception:
        return 15


def _requests_session() -> requests.Session:
    if requests is None:
        raise RuntimeError(
            "The 'requests' package is required. Install with: pip install requests"
        )
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": "CHARLOTTE-SBOM-Validator/1.0 (+https://c-h-a-r-l-o-t-t-e.org)",
            "Accept": "application/json",
        }
    )
    return s


# ──────────────────────────────────────────────────────────────────────────────
# Core Validator
# ──────────────────────────────────────────────────────────────────────────────


class SBOMValidator:
    def __init__(
        self,
        use_nvd: bool = False,
        deny_licenses: Iterable[str] | None = None,
        allow_licenses: Iterable[str] | None = None,
    ):
        self.use_nvd = use_nvd
        self.osv_url = os.getenv(
            "SBOM_VALIDATOR_OSV_URL", "https://api.osv.dev/v1/querybatch"
        )
        self.nvd_url = os.getenv(
            "SBOM_VALIDATOR_NVD_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"
        )
        self.nvd_api_key = os.getenv("NVD_API_KEY")
        self.session = _requests_session()
        self.deny_licenses = {x.strip().lower() for x in (deny_licenses or []) if x}
        self.allow_licenses = {x.strip().lower() for x in (allow_licenses or []) if x}

    # ── Parsing CycloneDX ──────────────────────────────────────────────────────
    def load_cyclonedx(self, path: Path) -> list[Component]:
        with open(path, encoding="utf-8") as f:
            cdx = json.load(f)

        if cdx.get("bomFormat", "").lower() != "cyclonedx":
            raise ValueError("Provided SBOM does not appear to be CycloneDX format")

        comps = []
        for comp in cdx.get("components", []) or []:
            name = str(comp.get("name", "")).strip()
            version = str(comp.get("version", "")).strip()
            if not name or not version:
                # CycloneDX SHOULD include both; skip otherwise
                continue

            purl = comp.get("purl")
            ecosystem, qualifiers = _parse_purl(purl) if purl else (None, {})
            # hashes
            h = {}
            for hh in comp.get("hashes", []) or []:
                alg = str(hh.get("alg")).upper()
                h[alg] = str(hh.get("content"))

            cid = purl or f"{name}@{version}"
            c = Component(
                id=cid,
                name=name,
                version=version,
                purl=purl,
                licenses=_extract_licenses(comp),
                hashes=h,
                ecosystem=ecosystem,
                qualifiers=qualifiers,
            )
            comps.append(c)
        return comps

    # ── License policy ─────────────────────────────────────────────────────────
    def check_licenses(self, c: Component) -> list[str]:
        """
        Very simple policy:
        - If deny list present: flag any component whose license matches deny list
        - If allow list present (and deny is empty): flag anything not in allow list
        """
        reasons = []
        # normalize
        comp_lics = [lic.lower() for lic in (c.licenses or [])]
        if self.deny_licenses:
            for lic in comp_lics:
                if lic in self.deny_licenses:
                    reasons.append(f"Denied license: {lic}")
        elif self.allow_licenses:
            # if none match, flag
            if not any(lic in self.allow_licenses for lic in comp_lics):
                reasons.append(
                    f"License not in allow list: {', '.join(c.licenses or ['(none)'])}"
                )
        return reasons

    # ── OSV (primary) ─────────────────────────────────────────────────────────
    def query_osv(
        self, components: list[Component]
    ) -> dict[str, list[VulnerabilityRef]]:
        """
        Use OSV batch endpoint: https://osv.dev/docs/#tag/OSV-API/operation/OSVService_QueryBatch
        - Prefer purl if available; else use ecosystem+name+version if we can derive
        """
        queries = []
        idx_map = []  # map back to component ids
        for c in components:
            if c.purl:
                queries.append({"package": {"purl": c.purl}, "version": c.version})
                idx_map.append(c.id)
            elif c.ecosystem:
                queries.append(
                    {
                        "package": {"name": c.name, "ecosystem": c.ecosystem},
                        "version": c.version,
                    }
                )
                idx_map.append(c.id)
            else:
                # last-resort: OSV may not match well; skip
                idx_map.append(None)
                queries.append(None)

        # prune None queries
        batch = [q for q in queries if q]
        if not batch:
            return {}

        # Keep a canonical payload object for chunking & potential debugging/metrics
        payload = {"queries": batch}
        out: dict[str, list[VulnerabilityRef]] = {}

        # OSV allows ~100 queries per batch; we’ll chunk
        CHUNK = 90
        for i in range(0, len(payload["queries"]), CHUNK):
            # Build the request from the canonical payload
            chunk = {"queries": payload["queries"][i : i + CHUNK]}
            for attempt in range(3):
                try:
                    r = self.session.post(self.osv_url, json=chunk, timeout=_timeout())
                    if r.status_code == 429:
                        time.sleep(2**attempt)
                        continue
                    r.raise_for_status()
                    data = r.json()
                    results = data.get("results", []) or []

                    # Build a local list of component ids matching this chunk
                    chunk_ids = [idx_map[j] for j, q in enumerate(queries) if q][
                        i : i + CHUNK
                    ]

                    # Use an explicit position cursor to map results → components,
                    # robust even if OSV returns fewer/more items than requested.
                    pos = 0
                    for res in results:
                        comp_id = chunk_ids[pos] if pos < len(chunk_ids) else None
                        pos += 1

                        vulns = []
                        for v in res.get("vulns", []) or []:
                            # prefer CVE id if present
                            aliases = v.get("aliases", []) or []
                            cve = next(
                                (a for a in aliases if a.startswith("CVE-")),
                                v.get("id"),
                            )
                            sev_label, sev_score = None, None
                            # OSV severity entries: [{"type": "CVSS_V3", "score": "7.5"}]
                            for sev in v.get("severity", []) or []:
                                if sev.get("type", "").upper().startswith("CVSS"):
                                    try:
                                        sev_score = float(sev.get("score"))
                                    except Exception:
                                        pass
                            norm = _norm_severity(sev_label, sev_score)
                            vulns.append(
                                VulnerabilityRef(
                                    source="OSV",
                                    id=cve or v.get("id"),
                                    severity=norm,
                                    cvss_score=sev_score,
                                    summary=v.get("summary"),
                                    url=(v.get("references") or [{}])[0].get("url"),
                                )
                            )
                        if comp_id:
                            out.setdefault(comp_id, []).extend(vulns)
                    break
                except Exception as e:
                    if attempt == 2:
                        print(f"[OSV] batch failed: {e}", file=sys.stderr)
        return out

    # ── NVD (optional) ────────────────────────────────────────────────────────
    def query_nvd_by_cpe_or_keyword(self, c: Component) -> list[VulnerabilityRef]:
        """
        NVD 2.0 API is trickier (CPEs). As a pragmatic starter:
        - If purl exists, we use its name + version as keyword search
        - Otherwise, name+version keyword search
        This is noisy; OSV should be primary. Use NVD for enrichment.
        """
        params = {
            "keywordSearch": f"{c.name} {c.version}",
            "startIndex": 0,
            "resultsPerPage": 100,
        }
        headers = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key

        vulns: list[VulnerabilityRef] = []
        try:
            r = self.session.get(
                self.nvd_url, params=params, headers=headers, timeout=_timeout()
            )
            if r.status_code == 429:
                time.sleep(1.5)
                r = self.session.get(
                    self.nvd_url, params=params, headers=headers, timeout=_timeout()
                )
            r.raise_for_status()
            data = r.json()
            for item in data.get("vulnerabilities", []) or []:
                cve = item.get("cve", {})
                cve_id = cve.get("id")
                metrics = cve.get("metrics", {})
                score = None
                # Try CVSS v3.x first
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    arr = metrics.get(key) or []
                    if arr:
                        try:
                            score = float(arr[0]["cvssData"]["baseScore"])
                            break
                        except Exception:
                            pass
                severity = _norm_severity(None, score)
                vulns.append(
                    VulnerabilityRef(
                        source="NVD",
                        id=cve_id or "NVD-UNKNOWN",
                        severity=severity,
                        cvss_score=score,
                        summary=(cve.get("descriptions") or [{}])[0].get("value"),
                        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                        if cve_id
                        else None,
                    )
                )
        except Exception as e:
            print(f"[NVD] query failed for {c.name}@{c.version}: {e}", file=sys.stderr)
        return vulns

    # ── Orchestrate ───────────────────────────────────────────────────────────
    def validate(self, components: list[Component]) -> list[Finding]:
        osv_map = self.query_osv(components)
        findings: list[Finding] = []

        for c in components:
            f = Finding(component_id=c.id, name=c.name, version=c.version, purl=c.purl)
            # License policy
            f.license_flags = self.check_licenses(c)

            # OSV vulns
            for v in osv_map.get(c.id, []):
                f.issues.append(v)

            # Optional NVD enrichment
            if self.use_nvd:
                for v in self.query_nvd_by_cpe_or_keyword(c):
                    # Avoid dup CVE ids
                    if v.id and all(v.id != exist.id for exist in f.issues):
                        f.issues.append(v)

            # Sort issues by severity (CRITICAL→LOW→UNKNOWN), then score desc
            f.issues.sort(
                key=lambda x: (
                    SEVERITY_ORDER.index(x.severity or "UNKNOWN"),
                    -(x.cvss_score or -1e9),
                )
            )
            findings.append(f)

        return findings

    # ── Reports ───────────────────────────────────────────────────────────────
    @staticmethod
    def to_json(findings: list[Finding], path: Path | None = None) -> str:
        payload = [asdict(f) for f in findings]
        text = json.dumps(payload, indent=2)
        if path:
            path.write_text(text, encoding="utf-8")
        return text

    @staticmethod
    def to_csv(findings: list[Finding], path: Path) -> None:
        with path.open("w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(
                [
                    "component_id",
                    "name",
                    "version",
                    "purl",
                    "issue_source",
                    "issue_id",
                    "severity",
                    "cvss_score",
                    "summary",
                    "url",
                    "license_flags",
                ]
            )
            for fr in findings:
                if fr.issues:
                    for v in fr.issues:
                        w.writerow(
                            [
                                fr.component_id,
                                fr.name,
                                fr.version,
                                fr.purl or "",
                                v.source,
                                v.id,
                                v.severity or "",
                                v.cvss_score or "",
                                (v.summary or "")[:200].replace("\n", " "),
                                v.url or "",
                                "; ".join(fr.license_flags) or "",
                            ]
                        )
                else:
                    # still emit a row to show “no issues”
                    w.writerow(
                        [
                            fr.component_id,
                            fr.name,
                            fr.version,
                            fr.purl or "",
                            "",
                            "",
                            "",
                            "",
                            "NO KNOWN VULNS",
                            "",
                            "; ".join(fr.license_flags) or "",
                        ]
                    )


# ──────────────────────────────────────────────────────────────────────────────
# CHARLOTTE Plugin Entrypoints
# ──────────────────────────────────────────────────────────────────────────────


def run(
    sbom_path: str,
    out_json: str | None = None,
    out_csv: str | None = None,
    use_nvd: bool = False,
    deny_licenses: list[str] | None = None,
    allow_licenses: list[str] | None = None,
) -> dict[str, Any]:
    """
    Primary programmatic entrypoint (used by CHARLOTTE).
    Returns a dict with 'summary' + 'findings'.
    """
    validator = SBOMValidator(
        use_nvd=use_nvd, deny_licenses=deny_licenses, allow_licenses=allow_licenses
    )
    comps = validator.load_cyclonedx(Path(sbom_path))
    findings = validator.validate(comps)

    # Save reports if requested
    if out_json:
        SBOMValidator.to_json(findings, Path(out_json))
    if out_csv:
        SBOMValidator.to_csv(findings, Path(out_csv))

    # Build a quick summary
    totals = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "MODERATE": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }
    affected = 0
    for f in findings:
        if f.issues:
            affected += 1
        for v in f.issues:
            totals[_norm_severity(v.severity, v.cvss_score)] += 1

    summary = {
        "components": len(comps),
        "affected_components": affected,
        "issue_counts": totals,
        "nvd_enriched": bool(use_nvd),
    }
    return {"summary": summary, "findings": [asdict(f) for f in findings]}


def run_plugin(config: dict[str, Any]) -> dict[str, Any]:
    """
    CHARLOTTE plugin shim — expects keys:
      config["sbom_path"] (str, required)
      config["out_json"] (str, optional)
      config["out_csv"] (str, optional)
      config["use_nvd"] (bool, optional)
      config["deny_licenses"] (list[str], optional)
      config["allow_licenses"] (list[str], optional)
    """
    sbom_path = config.get("sbom_path")
    if not sbom_path:
        raise ValueError("sbom_path is required")
    return run(
        sbom_path=sbom_path,
        out_json=config.get("out_json"),
        out_csv=config.get("out_csv"),
        use_nvd=bool(config.get("use_nvd", False)),
        deny_licenses=config.get("deny_licenses"),
        allow_licenses=config.get("allow_licenses"),
    )


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Validate CycloneDX SBOM using OSV/NVD")
    p.add_argument("--sbom", required=True, help="Path to CycloneDX JSON SBOM")
    p.add_argument("--out-json", help="Write findings to JSON")
    p.add_argument("--out-csv", help="Write findings to CSV")
    p.add_argument("--use-nvd", action="store_true", help="Also query NVD (enrichment)")
    p.add_argument(
        "--deny-license",
        action="append",
        default=[],
        help="Deny-list licenses (e.g., GPL-3.0-only). Repeatable.",
    )
    p.add_argument(
        "--allow-license",
        action="append",
        default=[],
        help="Allow-list licenses; if set (and deny empty) anything else is flagged.",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        result = run(
            sbom_path=args.sbom,
            out_json=args.out_json,
            out_csv=args.out_csv,
            use_nvd=args.use_nvd,
            deny_licenses=args.deny_license,
            allow_licenses=args.allow_license,
        )
        # Print a short console summary
        s = result["summary"]
        print(json.dumps(s, indent=2))
        return 0
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
