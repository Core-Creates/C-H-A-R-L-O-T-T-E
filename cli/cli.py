# ruff: noqa: E402
# Reason: this script adjusts sys.path before importing project modules.
# ******************************************************************************************
# CHARLOTTE CLI - Interactive Interface for the Cybernetic Heuristic Assistant
# Provides task selection, personality configuration, and scan execution via plugin engine.
# Also includes CHARLOTTE triage/gate subcommands for supply-chain triage integration.
# ******************************************************************************************

import os
import sys

# 🛠️ PATCH SYS.PATH EARLY — this must be before any CHARLOTTE imports!
CURRENT_FILE = os.path.abspath(__file__)
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(CURRENT_FILE), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# 🧠 All other imports now work:
import json
import inspect
from pathlib import Path
from typing import Any, Literal

# core project imports (unchanged)
from core import report_dispatcher
from core.charlotte_personality import CharlottePersonality
from plugins.recon.amass.owasp_amass import run_plugin as run_amass_plugin

# Third-party libs used by the triage/gate integration
# (Install with: pip install typer pydantic pyyaml)
import typer
from pydantic import BaseModel, Field
import yaml


# -----------------------------
# Existing helper: safe_run_plugin
# -----------------------------
def safe_run_plugin(func, **params):
    """
    Calls plugin functions that may accept different signatures:
    - single dict param (args/config/options)
    - specific named kwargs
    - positional-only parameters
    Also maps common synonyms like domain->target when needed.
    """
    sig = inspect.signature(func)
    param_names = list(sig.parameters.keys())

    # Map common synonyms
    mapped = dict(params)
    if (
        "domain" in params
        and "domain" not in sig.parameters
        and "target" in sig.parameters
    ):
        mapped["target"] = params["domain"]

    # If the function takes exactly one param, it often expects a dict
    if len(param_names) == 1:
        try:
            return func(mapped)
        except TypeError:
            # fall back: pass only what that single param is named (still a dict)
            return func({k: v for k, v in mapped.items()})

    # Otherwise try filtered kwargs first
    filtered = {k: v for k, v in mapped.items() if k in sig.parameters}
    try:
        return func(**filtered)
    except TypeError:
        # Last resort: positional in declared order (only those we have)
        ordered = [mapped[name] for name in param_names if name in mapped]
        return func(*ordered)


# ******************************************************************************************
# Plugin Task + Argument Setup (original content)
# ******************************************************************************************

PLUGIN_TASKS = {
    "🧠 Reverse Engineer Binary (Symbolic Trace)": "reverse_engineering",
    "🔍 Binary Strings + Entropy Analysis": "binary_strings",
    "🌐 Web Recon (Subdomains)": "web_recon",
    "📱 Nmap Network Scanner": "nmap_scan",
    "💉 SQL Injection Scan": "sql_injection",
    "🩺 XSS Scan": "xss_scan",
    "🚨 Exploit Generator": "exploit_generation",
    "🔎 OWASP Amass Subdomain Recon": "owasp_amass",
    "🧮 Vulnerability Triage (Score + Prioritize)": "triage_agent",
}

REQUIRED_ARGS = {
    "reverse_engineering": ["file"],
    "binary_strings": ["file"],
    "web_recon": ["domain"],
    "nmap_scan": ["target", "ports"],
    "sql_injection": ["url"],
    "xss_scan": ["url"],
    "exploit_generation": ["vuln_description"],
    "owasp_amass": ["domain"],
}

PLUGIN_DOCS = {
    "binary_strings": "Extract printable ASCII strings from binaries and score them by entropy to highlight suspicious or encoded data.",
    "reverse_engineering": "Symbolically trace executable behavior without runtime execution to analyze malware or reverse binaries.",
    "web_recon": "Perform DNS recon to identify subdomains and expand attack surface for web targets.",
    "nmap_scan": "Run an interactive Nmap scan using various techniques like SYN, UDP, or Aggressive scan modes.",
    "sql_injection": "Test URLs for injectable parameters that can expose or manipulate database contents.",
    "xss_scan": "Identify reflected or stored cross-site scripting flaws in web applications.",
    "exploit_generation": "Use LLMs or rule-based templates to generate proof-of-concept exploits from vulnerability descriptions.",
    "owasp_amass": "Run OWASP Amass to enumerate subdomains using passive DNS and other sources.",
}

# List of CHARLOTTE's predefined mood+tone profiles available to the user
PREDEFINED_MODES = [
    "goth_queen",
    "mischief",
    "gremlin_mode",
    "professional",
    "apathetic_ai",
]

# ******************************************************************************************
# Personality Configuration (original content)
# ******************************************************************************************


def load_personality_config(path="personality_config.json"):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_personality_config(config, path="personality_config.json"):
    with open(path, "w") as f:
        json.dump(config, f, indent=4)


def create_charlotte_from_config(config):
    mode = config.get("mode", "goth_queen")
    sass = config.get("sass", 0.5)
    sarcasm = config.get("sarcasm", 0.5)
    chaos = config.get("chaos", 0.5)
    return CharlottePersonality(sass=sass, sarcasm=sarcasm, chaos=chaos, mode=mode)


# ******************************************************************************************
# Plugin Documentation Helper (original content)
# ******************************************************************************************


def check_plugin_doc():
    for arg in sys.argv:
        if arg.startswith("--doc"):
            try:
                plugin_key = sys.argv[sys.argv.index(arg) + 1]
                if plugin_key in PLUGIN_DOCS:
                    print(f"\n🗾 CHARLOTTE Plugin Help: {plugin_key}\n")
                    print(PLUGIN_DOCS[plugin_key])
                else:
                    print(
                        f"\n[!] Unknown plugin '{plugin_key}'. Try one of: {', '.join(PLUGIN_DOCS.keys())}"
                    )
            except IndexError:
                print(
                    "[!] Please specify a plugin after --doc (e.g., --doc binary_strings)"
                )
            sys.exit(0)


# ******************************************************************************************
# Report Helper (original content)
# ******************************************************************************************


def handle_report(report_data):
    if not report_data:
        print("[!] No report data returned.")
        return
    file_path = report_dispatcher.save_report_locally(report_data, interactive=False)
    report_dispatcher.dispatch_report(file_path)


# ******************************************************************************************
# Task Explanation Handler (original content)
# ******************************************************************************************


def explain_task(task, mood):
    print("\n🥪 CHARLOTTE says:")
    if task == "binary_strings":
        if mood == "sassy":
            print(
                "  Honey, entropy is just chaos — measured mathematically.\n  If it looks random and sus, it probably is. Let’s dig in.\n"
            )
        elif mood == "brooding":
            print("  Entropy... the measure of disorder. Like code. Like people.\n")
        elif mood == "manic":
            print("  OMG! High entropy = ENCRYPTION! SECRETS! CHAOS! I love it!! 🤩\n")
        elif mood == "apathetic":
            print("  Entropy is a number. It’s whatever. Just run the scan.\n")
        else:
            print(
                "  Entropy measures how *random* or *unstructured* a string is.\n  Higher entropy often means encryption, encoding, or something suspicious.\n"
            )
    elif task == "reverse_engineering":
        print(
            "  Symbolic tracing helps analyze binary behavior without execution.\n  Useful for malware analysis or understanding complex binaries.\n"
        )
    elif task == "web_recon":
        print(
            "  Web recon helps discover hidden subdomains and potential attack surfaces.\n"
        )
    elif task == "owasp_amass":
        print(
            "  OWASP Amass performs passive or active subdomain enumeration.\n  Great for expanding your domain's footprint and finding weak spots.\n"
        )
    elif task == "nmap_scan":
        print(
            "  Nmap is my favorite. Classic recon, updated with heuristics.\n  Let’s scan and see what secrets your network is whispering.\n"
        )
    elif task == "sql_injection":
        print("  SQL injection scans look for vulnerabilities in web applications.\n")
    elif task == "xss_scan":
        print("  XSS scans detect cross-site scripting vulnerabilities in web apps.\n")
    elif task == "exploit_generation":
        print(
            "  Exploit generation creates payloads based on vulnerability descriptions.\n"
        )


# ******************************************************************************************
# CHARLOTTE TRIAGE / GATE INTEGRATION (adapted & embedded)
# - Keeps the Pydantic models and simple scoring model from the skeleton.
# - Exposes `triage` and `gate` as Typer subcommands while preserving original script behavior.
# ******************************************************************************************

app = typer.Typer(help="CHARLOTTE CLI (interactive + triage/gate)")

Severity = Literal["critical", "high", "medium", "low", "none"]


class Component(BaseModel):
    name: str
    version: str | None = None
    purl: str | None = None  # package URL if available
    type: str | None = None  # library, application, container, etc.


class Evidence(BaseModel):
    sources: list[str] = Field(
        default_factory=list
    )  # e.g., links to advisories, scan IDs
    notes: str | None = None


class TriageItem(BaseModel):
    id: str  # CVE, GHSA, or vendor ID
    title: str | None = None
    component: Component
    severity: Severity = "medium"
    cwe: str | None = None
    vector: str | None = None  # CVSS vector
    cvss: float | None = None
    epss: float | None = None  # Exploit Prediction Scoring System (0-1)
    kev: bool = False  # On CISA KEV list?
    reachable: bool | None = None  # code-level reachability (placeholder)
    exposure: str | None = None  # internet, internal, none
    fix_version: str | None = None
    dependency_path: list[str] | None = None
    exploit_present: bool | None = None  # POC or module available
    risk_score: float | None = None
    owner: str | None = None
    sla: str | None = None
    evidence: Evidence = Field(default_factory=Evidence)


class TriageBundle(BaseModel):
    tool: str = "charlotte"
    version: str = "0.0.1"
    repo: str | None = None
    commit: str | None = None
    items: list[TriageItem] = Field(default_factory=list)


class Policy(BaseModel):
    fail_on_severity: list[Severity] = Field(
        default_factory=lambda: ["critical", "high"]
    )  # default gate
    min_risk_score_fail: float | None = 0.85
    sla_by_severity: dict[Severity, str] = Field(
        default_factory=lambda: {
            "critical": "72h",
            "high": "7d",
            "medium": "30d",
            "low": "90d",
            "none": "none",
        }
    )


_sev_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def parse_policy(policy_path: Path | None) -> Policy:
    if policy_path and policy_path.exists():
        return Policy(**load_yaml(policy_path))
    return Policy()


def map_snyk_to_triage(snyk: dict[str, Any]) -> list[TriageItem]:
    """
    Map a Snyk JSON output (test --json) to triage items.
    Supports both 'vulnerabilities' (older) and 'issues.vulnerabilities' (newer) shapes.
    """
    items: list[TriageItem] = []

    vulns = []
    if isinstance(snyk, dict):
        if "vulnerabilities" in snyk:
            vulns = snyk.get("vulnerabilities", [])
        elif "issues" in snyk and isinstance(snyk["issues"], dict):
            vulns = snyk["issues"].get("vulnerabilities", [])

    for v in vulns:
        pkg_name = v.get("packageName") or v.get("package") or "unknown"
        comp = Component(
            name=pkg_name,
            version=v.get("version"),
            purl=v.get("purl"),
            type=v.get("packageManager"),
        )
        sev = (v.get("severity") or "medium").lower()
        sev = sev if sev in _sev_map else "medium"
        identifiers = v.get("identifiers", {})
        cve = None
        if isinstance(identifiers, dict):
            cve_list = identifiers.get("CVE") or identifiers.get("cve") or []
            if isinstance(cve_list, list) and len(cve_list) > 0:
                cve = cve_list[0]
        if not cve:
            cve = v.get("id") or "UNKNOWN"

        items.append(
            TriageItem(
                id=cve,
                title=v.get("title"),
                component=comp,
                severity=sev,  # type: ignore
                cwe=(identifiers.get("CWE") or [None])[0]
                if isinstance(identifiers, dict)
                else None,
                vector=v.get("CVSSv3"),
                cvss=(v.get("cvssScore") or v.get("cvssScoreV3")),
                fix_version=(
                    v.get("fixVersion") or (v.get("upgradePaths") or [[None]])[0][-1]
                ),
                dependency_path=v.get("from"),
                evidence=Evidence(sources=[str(v.get("id") or cve)]),
            )
        )
    return items


def parse_sbom_components(sbom: dict[str, Any]) -> dict[str, Component]:
    """Parse CycloneDX (preferred) or SPDX JSON minimally into a component map by name."""
    components: dict[str, Component] = {}

    if "components" in sbom:  # CycloneDX
        for c in sbom.get("components", []):
            name = c.get("name")
            if not name:
                continue
            components[name] = Component(
                name=name,
                version=c.get("version"),
                purl=c.get("purl"),
                type=c.get("type"),
            )
    elif "packages" in sbom:  # SPDX
        for p in sbom.get("packages", []):
            name = p.get("name") or p.get("packageName")
            if not name:
                continue
            components[name] = Component(
                name=name,
                version=p.get("versionInfo") or p.get("packageVersion"),
                purl=None,
                type="library",
            )
    return components


def compute_risk_score(item: TriageItem) -> float:
    """Toy scoring model. Replace with your exploit-aware + reachability model."""
    base = _sev_map.get(item.severity, 2) / 4  # 0..1
    cvss = (item.cvss or 0) / 10  # 0..1
    epss = item.epss or 0  # 0..1
    kev_boost = 0.15 if item.kev else 0
    exploit_boost = 0.15 if (item.exploit_present) else 0
    reach = 0.1 if (item.reachable) else 0

    score = 0.5 * base + 0.3 * cvss + 0.2 * epss + kev_boost + exploit_boost + reach
    return min(score, 1.0)


def apply_policy_metadata(item: TriageItem, policy: Policy) -> TriageItem:
    item.risk_score = compute_risk_score(item)
    item.sla = policy.sla_by_severity.get(item.severity)
    return item


# -----------------------------
# Typer subcommand: triage
# -----------------------------
@app.command()
def triage(
    snyk: Path = typer.Option(
        ..., exists=True, readable=True, help="Path to Snyk JSON output"
    ),
    sbom: Path | None = typer.Option(
        None, exists=True, readable=True, help="Path to SBOM (CycloneDX/SPDX JSON)"
    ),
    out: Path = typer.Option(Path("triage.json"), help="Output triage bundle JSON"),
    policy: Path | None = typer.Option(
        None, exists=True, readable=True, help="Policy YAML (optional)"
    ),
    repo: str | None = typer.Option(None, help="Repository identifier"),
    commit: str | None = typer.Option(None, help="Commit SHA"),
):
    """
    Ingest Snyk + SBOM and produce a CHARLOTTE triage bundle.
    """
    try:
        snyk_obj = load_json(snyk)
    except Exception as e:
        typer.echo(f"[!] Failed to load Snyk JSON: {e}", err=True)
        raise typer.Exit(code=2)

    items = map_snyk_to_triage(snyk_obj)

    comp_map: dict[str, Component] = {}
    if sbom:
        try:
            comp_map = parse_sbom_components(load_json(sbom))
        except Exception as e:
            typer.echo(f"[!] Failed to parse SBOM: {e}", err=True)
            raise typer.Exit(code=2)

    pol = parse_policy(policy)

    # Merge component metadata from SBOM & enrich
    enriched: list[TriageItem] = []
    for it in items:
        c = comp_map.get(it.component.name)
        if c:
            # prefer SBOM version/purl if missing
            it.component.version = it.component.version or c.version
            it.component.purl = it.component.purl or c.purl
            it.component.type = it.component.type or c.type
        it = apply_policy_metadata(it, pol)
        enriched.append(it)

    bundle = TriageBundle(
        tool="charlotte", version="0.0.1", repo=repo, commit=commit, items=enriched
    )
    out.write_text(bundle.model_dump_json(indent=2), encoding="utf-8")
    typer.echo(f"Wrote triage bundle → {out}")


# -----------------------------
# Typer subcommand: gate
# -----------------------------
@app.command()
def gate(
    input: Path = typer.Option(
        ..., exists=True, readable=True, help="Path to triage bundle JSON"
    ),
    fail_on: list[Severity] = typer.Option(
        [],
        help="Fail if any item has one of these severities (overrides policy if set)",
    ),
    min_risk_fail: float | None = typer.Option(
        None, help="Fail if any item risk_score >= this threshold (0..1)"
    ),
    policy: Path | None = typer.Option(
        None, exists=True, readable=True, help="Policy YAML (optional)"
    ),
    print_summary: bool = typer.Option(True, help="Print a short summary table"),
):
    """
    Evaluate triage bundle against gate policy and exit non-zero on failure.
    """
    try:
        data = json.loads(input.read_text(encoding="utf-8"))
        bundle = TriageBundle(**data)
    except Exception as e:
        typer.echo(f"[!] Failed to load triage bundle: {e}", err=True)
        raise typer.Exit(code=2)

    pol = parse_policy(policy)
    fail_sevs = fail_on or pol.fail_on_severity
    risk_threshold = (
        min_risk_fail if min_risk_fail is not None else pol.min_risk_score_fail
    )

    offenders: list[tuple[str, str, float]] = []

    for it in bundle.items:
        sev_fail = it.severity in fail_sevs
        risk = it.risk_score if it.risk_score is not None else compute_risk_score(it)
        risk_fail = (risk_threshold is not None) and (risk >= risk_threshold)
        if sev_fail or risk_fail:
            offenders.append((it.id, it.severity, float(risk)))

    if print_summary:
        typer.echo("\nGate Summary:")
        typer.echo(f"  Items: {len(bundle.items)}")
        typer.echo(f"  Fail-on severities: {fail_sevs}")
        typer.echo(f"  Min risk threshold: {risk_threshold}")
        if offenders:
            typer.echo("  Offenders:")
            for oid, sev, risk in offenders:
                typer.echo(f"    - {oid} | {sev} | risk={risk:.2f}")
        else:
            typer.echo("  No offenders. ✅")

    if offenders:
        typer.echo("\nGate: FAIL", err=True)
        raise typer.Exit(code=1)
    else:
        typer.echo("\nGate: PASS")
        raise typer.Exit(code=0)


# ******************************************************************************************
# Entry Point Logic (preserve original default behavior)
# - If script is invoked with no args, run original amass plugin flow (unchanged).
# - If script is invoked with any args/subcommands, let Typer handle them.
# ******************************************************************************************


def run_default_amass_flow():
    """
    This preserves the original script's behavior: run the amass plugin and dispatch the report.
    """
    # Use the shim so we don't care how the plugin’s signature looks
    result = safe_run_plugin(
        run_amass_plugin, domain="www.c-h-a-r-l-o-t-t-e.org", interactive=False
    )
    handle_report(result)


def main():
    # If no command-line args provided (other than script name), preserve original behavior.
    if len(sys.argv) == 1:
        run_default_amass_flow()
        return

    # Otherwise dispatch Typer app (triage/gate + possibly future commands)
    app()


# ******************************************************************************************
# This is the main entry point for the CHARLOTTE CLI.
# ******************************************************************************************
if __name__ == "__main__":
    main()
# ******************************************************************************************
# End of cli/cli.py
# ******************************************************************************************
