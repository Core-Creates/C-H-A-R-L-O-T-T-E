"""
nmap_plugin.py - CHARLOTTE plugin for interactive and chained Nmap scanning.

Supports multiple scan types (TCP SYN, Connect, UDP, OS detection, etc.)
Handles plugin chaining and saves results to timestamped folders.
Now optionally enriches results with GHDB intel based on open ports/banners.

Author: CHARLOTTE (network voyeur extraordinaire)
"""

import os
import sys
import json
import re
from datetime import datetime
from typing import Dict, Any, List

# Dynamically locate CHARLOTTE root and add to Python path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../"))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Path helper (robust import)
try:
   from utils.paths import display_path        # preferred location+
except Exception:
    try:
        from paths import display_path          # fallback if paths.py is at repo root
    except Exception:
       # last-resort shim so nothing crashes
        def display_path(path: str, base: str | None = None) -> str:
            return str(path).replace("\\", "/")
# GHDB provider
from plugins.intell.google_dorks.dorks import ghdb

# Optional: path utilities
# Prefer the real location
try:
    from utils.paths import display_path
except Exception:
    # Optional fallback if you ever relocate it in the future
    try:
        from utils.paths import display_path  # legacy
    except Exception:
        # Final safety: minimal inline shim so nothing crashes
        def display_path(path: str, base: str | None = None) -> str:
            return str(path).replace("\\", "/")

# Optional: rich table
try:
    from tabulate import tabulate
except Exception:  # pragma: no cover
    tabulate = None

# Optional scoring/heuristics module
try:
    from core.logic_modules import recon_heuristics
except Exception:  # pragma: no cover
    recon_heuristics = None

# Optional linker (preferred if available)
try:
    from plugins.intell.google_dorks.ghdb_linker import suggest_from_nmap as _suggest_from_nmap
except Exception:  # pragma: no cover
    _suggest_from_nmap = None

# python-nmap
import nmap

# ──────────────────────────────────────────────────────────────────────────────
# Scan types (menu)
# ──────────────────────────────────────────────────────────────────────────────
SCAN_TYPES = {
    "1": {"name": "TCP SYN Scan", "arg": "-sS", "description": "Stealthy, fast TCP scan (default)"},
    "2": {"name": "TCP Connect Scan", "arg": "-sT", "description": "Standard TCP connect scan"},
    "3": {"name": "UDP Scan", "arg": "-sU", "description": "Scan for open UDP ports"},
    "4": {"name": "Service Version Detection", "arg": "-sV", "description": "Detect service versions"},
    "5": {"name": "OS Detection", "arg": "-O", "description": "Try to identify the target OS"},
    "6": {"name": "Aggressive Scan", "arg": "-A", "description": "All-in-one: OS, services, scripts"},
    "7": {"name": "Ping Scan", "arg": "-sn", "description": "Discover live hosts (no port scan)"},
}

# ──────────────────────────────────────────────────────────────────────────────
# Device settings management
# ──────────────────────────────────────────────────────────────────────────────
DEVICE_SETTINGS_PATH = "data/device_settings.json"

def load_device_settings():
    if os.path.exists(DEVICE_SETTINGS_PATH):
        with open(DEVICE_SETTINGS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_device_settings(settings):
    os.makedirs(os.path.dirname(DEVICE_SETTINGS_PATH), exist_ok=True)
    # write atomically
    tmp_path = DEVICE_SETTINGS_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=4)
    os.replace(tmp_path, DEVICE_SETTINGS_PATH)

def assign_priority_by_score(score: int) -> str:
    if score >= 80:
        return "High"
    if score >= 50:
        return "Medium"
    return "Low"

def prompt_device_priority(host: str, default_score: int) -> str:
    print(f"\n[🧠 CHARLOTTE says:] \"Let's rank {host} based on how juicy it looks...\"")
    print(f"  Heuristic Score: {default_score}")
    if default_score >= 80:
        suggested = "High"
    elif default_score >= 50:
        suggested = "Medium"
    else:
        suggested = "Low"
    print(f"  → Suggested: {suggested}")
    priority = input(f"Enter priority for {host} [High/Medium/Low] (default: {suggested}): ").strip().capitalize()
    if priority not in {"High", "Medium", "Low"}:
        print(f"[!] Invalid input. Defaulting to {suggested}.")
        priority = suggested
    return priority

def extract_services_for_msf(nmap_json_path):
    """Extract likely-exploitable services from our saved JSON (host → ports dict)."""
    with open(nmap_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    candidates = []
    for host, results in data.items():
        for port, svc in results.get("ports", {}).items():
            name = str(svc.get("name", "")).lower()
            if any(k in name for k in ("http", "smb", "ftp", "ssh", "rdp", "rpc")):
                candidates.append((host, name, int(port)))
    return candidates

# ──────────────────────────────────────────────────────────────────────────────
# UI helpers
# ──────────────────────────────────────────────────────────────────────────────
def list_scan_options():
    print("\n[CHARLOTTE] Available Nmap Scan Types:\n")
    for key, scan in SCAN_TYPES.items():
        print(f"  {key}. {scan['name']} – {scan['description']}")

def choose_scan():
    while True:
        choice = input("\nSelect scan type by number: ").strip()
        if choice in SCAN_TYPES:
            return SCAN_TYPES[choice]
        print("[!] Invalid choice. Try again.")

# ──────────────────────────────────────────────────────────────────────────────
# Core scan
# ──────────────────────────────────────────────────────────────────────────────
def _make_scanner():
    """
    Create a PortScanner. On Windows, allow override with NMAP_EXE env var:
      set NMAP_EXE=C:\\Program Files (x86)\\Nmap\\nmap.exe
    """
    nmap_path = os.environ.get("NMAP_EXE")
    if nmap_path:
        return nmap.PortScanner(nmap_search_path=nmap_path)
    return nmap.PortScanner()

def run_nmap_scan(scan_type, target, ports=None, output_dir="data/findings"):
    """
    Executes an Nmap scan with a given scan type and saves results.

    Output JSON shape:
    {
      "<host>": {
        "state": "up",
        "last_scanned": "<timestamp>",
        "ports": {
          "22": {"state":"open","name":"ssh","product":"OpenSSH","version":"8.4"},
          "80": {"state":"open","name":"http","product":"Apache httpd","version":"2.4.57"}
        },
        "heuristics": {"score": 73, "rating": "elevated", "findings": [...]}
      },
      ...
    }
    """
    os.makedirs(output_dir, exist_ok=True)
    scanner = _make_scanner()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir, f"nmap_{target.replace('/', '_')}_{timestamp}.json")
    port_arg = f"-p {ports}" if ports else ""

    try:
        print(f"\n[NMAP] {scan_type['name']} on {target} {f'(ports: {ports})' if ports else ''}")
        scanner.scan(hosts=target, arguments=f"{scan_type['arg']} {port_arg}")
    except Exception as e:
        print(f"[ERROR] Nmap failed on {target}: {e}")
        return None

    results = {}
    device_settings = load_device_settings()

    for host in scanner.all_hosts():
        host_state = scanner[host].state()
        ports_dict = {}

        for proto in scanner[host].all_protocols():
            for port in sorted(scanner[host][proto].keys()):
                entry = scanner[host][proto][port]
                # Normalize
                ports_dict[str(port)] = {
                    "state": entry.get("state", ""),
                    "name": entry.get("name", ""),
                    "product": entry.get("product", ""),
                    "version": entry.get("version", ""),
                    # proto stored so GHDB mapping can use it
                    "proto": proto,
                    # pass through CPE if python-nmap provided it
                    "cpe": entry.get("cpe", []) or entry.get("cpe23", []),
                    "extrainfo": entry.get("extrainfo", ""),
                }

        # Heuristics (optional)
        if recon_heuristics and hasattr(recon_heuristics, "triage_host"):
            host_record = [
                {
                    "port": int(p),
                    "name": v.get("name", ""),
                    "product": v.get("product", ""),
                    "version": v.get("version", "")
                }
                for p, v in ports_dict.items()
            ]
            heuristic_result = recon_heuristics.triage_host(host_record)
        else:
            heuristic_result = {"score": 50, "rating": "baseline", "findings": ["Heuristics module not available"]}

        # Priority (interactive vs headless)
        interactive = sys.stdin.isatty() and os.environ.get("CHARLOTTE_HEADLESS") != "1"
        if interactive:
            priority = prompt_device_priority(host, heuristic_result["score"])
        else:
            priority = assign_priority_by_score(heuristic_result["score"])
            print(f"[AUTO] Assigned priority '{priority}' for {host}")

        # Persist device settings
        device_settings[host] = {
            "priority": priority,
            "last_scanned": timestamp,
            "heuristic_score": heuristic_result["score"],
        }
        save_device_settings(device_settings)
        print(f"[💾 Saved priority '{priority}' for {host} to device_settings.json]")

        # Assemble result for this host
        results[host] = {
            "state": host_state,
            "last_scanned": timestamp,
            "ports": ports_dict,
            "heuristics": heuristic_result,
        }

        # Pretty print summary to console
        print(f"\nScan Results for {host} ({host_state})")
        for p, v in sorted(ports_dict.items(), key=lambda kv: int(kv[0])):
            banner = f"{v.get('product','')} {v.get('version','')}".strip()
            print(f"  {p}/{v.get('proto','tcp')}: {v.get('state','')}  {v.get('name','')}  {banner}")

        print(f"\n[⚙️  Heuristic Score: {heuristic_result['score']} - {heuristic_result['rating']}]")
        for finding in heuristic_result.get("findings", []):
            print(f"  → {finding}")

    # Save to disk
    os.makedirs(output_dir, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)

    print(f"\n[📁 Results saved to: {output_path}]")
    return output_path

# ──────────────────────────────────────────────────────────────────────────────
# GHDB linker (fallback if plugins.intell.google_dorks.ghdb_linker is not present)
# ──────────────────────────────────────────────────────────────────────────────
_SERVICE_SEEDS = {
    "http":  [r"intitle:\s*index\.of", r"inurl:admin", r"inurl:login", r"inurl:phpmyadmin", r"\"powered by\""],
    "https": [r"intitle:\s*index\.of", r"inurl:admin", r"inurl:login", r"inurl:phpmyadmin", r"\"powered by\""],
    "ftp":   [r"intitle:\s*index\.of\s+ftp", r"inurl:ftp", r"anonymous ftp", r"vsftpd"],
    "mysql": [r"inurl:phpmyadmin", r"intitle:phpmyadmin", r"intext:\"Welcome to phpMyAdmin\""],
    "postgresql": [r"inurl:pgadmin"],
    "mongodb": [r"mongo express", r"inurl:8081"],
    "rdp":   [r"inurl:tsweb", r"Remote Desktop Web Connection"],
    "rtsp":  [r"rtsp", r"intitle:\"Network Camera\"", r"inurl:view/view\.shtml"],
    "smtp":  [r"Roundcube", r"SquirrelMail", r"RainLoop", r"inurl:webmail"],
    "imap":  [r"inurl:webmail", r"Roundcube", r"SquirrelMail"],
}

_STOPWORDS = {"service", "server", "device", "unknown", "open", "ssl", "tls", "protocol", "daemon", "http", "https", "tcp", "udp"}

def _tok(s: str) -> List[str]:
    if not s:
        return []
    toks = re.split(r"[^A-Za-z0-9]+", s.lower())
    return [t for t in toks if len(t) >= 3 and t not in _STOPWORDS]

def _tokens_from_cpe(cpe: str) -> List[str]:
    if not cpe:
        return []
    parts = cpe.split(":")
    segs = []
    if len(parts) >= 4:
        segs.extend([parts[2], parts[3]])  # vendor, product
    if len(parts) >= 5 and parts[4]:
        segs.append(parts[4])  # version
    out = []
    for s in segs:
        out.extend(_tok(s.replace("_", " ")))
    return out

def _derive_service(port: int | None, name: str | None) -> str:
    if name:
        return name.lower()
    common = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        80: "http", 81: "http", 88: "http", 110: "pop3",
        143: "imap", 443: "https", 465: "smtps", 554: "rtsp",
        587: "submission", 993: "imaps", 995: "pop3s",
        3306: "mysql", 3389: "rdp", 5432: "postgresql",
        6379: "redis", 8080: "http", 8081: "http", 8443: "https",
    }
    return common.get(port or -1, "unknown")

def _build_or_regex(tokens: List[str], seeds: List[str], port: int | None) -> str:
    alts = set()
    for t in tokens:
        if t:
            alts.add(re.escape(t))
    for s in seeds:
        if s:
            alts.add(s)  # seeds are regex snippets already
    if port in (81, 88, 8000, 8008, 8080, 8081, 8181, 8443, 8888):
        alts.add(str(port))
    if not alts:
        return r"(?!)"  # match nothing
    return "(" + "|".join(sorted(alts)) + ")"

def _suggest_from_nmap_fallback(scan_results: Dict[str, Any], source="dump", limit_per_port=20, extra_grep=None, debug=False):
    # Pull GHDB rows once
    rows = ghdb.query(source=source, limit=None, grep=None, debug=debug)
    out: Dict[str, List[Dict[str, Any]]] = {}

    def filt(rows, pattern):
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error:
            rx = re.compile(re.escape(pattern), re.IGNORECASE)
        m = []
        for r in rows:
            if rx.search(r.get("dork") or "") or rx.search(r.get("title") or ""):
                m.append(r)
        return m

    for host in (scan_results.get("hosts") or []):
        ip = host.get("ip") or host.get("host") or host.get("address") or "unknown"
        for p in (host.get("ports") or []):
            port = p.get("port") or p.get("portid")
            svc = _derive_service(port, p.get("service") or p.get("name"))
            product = p.get("product") or ""
            version = p.get("version") or ""
            extrainfo = p.get("extrainfo") or ""
            cpes = p.get("cpe") or p.get("cpes") or []

            tokens = set()
            tokens.update(_tok(svc))
            tokens.update(_tok(product))
            tokens.update(_tok(version))
            tokens.update(_tok(extrainfo))
            for c in (cpes if isinstance(cpes, list) else [cpes]):
                tokens.update(_tokens_from_cpe(c))

            seeds = _SERVICE_SEEDS.get(svc, [])
            pattern = _build_or_regex(list(tokens), seeds, port)
            if extra_grep:
                pattern = f"(?:{pattern})|(?:{extra_grep})"

            matches = filt(rows, pattern)

            # light rank: occurrences of product tokens
            if product:
                prod_words = set(_tok(product))
                def score(row):
                    txt = (row.get("dork") or "") + " " + (row.get("title") or "")
                    low = txt.lower()
                    return sum(1 for w in prod_words if w and w in low)
                matches.sort(key=score, reverse=True)

            key = f"{ip}:{port}/{p.get('proto','tcp')} {svc} {product} {version}".strip()
            out[key] = matches[:limit_per_port]
    return out

# ──────────────────────────────────────────────────────────────────────────────
# Plugin entry point (manager-compatible) + GHDB enrichment (FULL result)
# ──────────────────────────────────────────────────────────────────────────────
def run_plugin_full(args=None, output_dir="data/findings"):
    """
    CHARLOTTE plugin entry point. Signature is manager-compatible.

    Behavior:
      - Headless chaining:
          args = {"targets": ["10.0.0.5", "10.0.0.6"], "scan_type": "-sV", "ports": "1-1024",
                  "ghdb": True, "ghdb_limit": 15, "ghdb_grep": "wordpress|joomla", "ghdb_source": "dump"}
      - Interactive:
          no args or no 'targets' -> show menu + prompt user

    Returns (extended):
      {
        "task": "port_scan",
        "status": "ok",
        "output_paths": [...],
        "results": { "hosts": [ { "ip": ..., "ports": [...] }, ... ] },
        "intel": { "ghdb": { "<key>": [<entries>], ... } }
      }
    """
    os.makedirs(output_dir, exist_ok=True)

    # Extract args
    targets = args.get("target")
    scan_flag = None
    ports = args.get("ports")
    ghdb_enabled = True
    ghdb_source = "dump"
    ghdb_limit = 15
    ghdb_grep = None
    ghdb_debug = False

    # if isinstance(args, dict):
    #     targets = args.get("targets")
    #     scan_flag = args.get("scan_type")  # e.g. "-sV"
    #     ports = args.get("ports")
    #     output_dir = args.get("output_dir", output_dir)
    #     ghdb_enabled = bool(args.get("ghdb", True))
    #     ghdb_source = args.get("ghdb_source", "dump")
    #     ghdb_limit = int(args.get("ghdb_limit", 15))
    #     ghdb_grep = args.get("ghdb_grep")
    #     ghdb_debug = bool(args.get("debug", False))

    output_paths: List[str] = []

    
    # Headless: default to -sV unless caller overrides
    chosen = next((v for v in SCAN_TYPES.values() if v["arg"] == (scan_flag or "-sV")), None)
    if not chosen:
        chosen = SCAN_TYPES["4"]  # Service Version Detection
    for host in targets:
        path = run_nmap_scan(chosen, host, ports=ports, output_dir=output_dir)
        if path:
            output_paths.append(path)
    # else:
    #     # Interactive mode
    #     list_scan_options()
    #     chosen = choose_scan()
    #     target = input("\nEnter target IP or domain (comma-separated for multiple): ").strip()
    #     ports = input("Enter port(s) to scan (e.g. 22,80 or 1-1000) [optional]: ").strip()
    #     targets = [t.strip() for t in target.split(",") if t.strip()]
    #     for host in targets:
    #         path = run_nmap_scan(chosen, host, ports=ports or None, output_dir=output_dir)
    #         if path:
    #             output_paths.append(path)

    # Build a unified scan_result (hosts/ports) from saved JSONs for downstream consumers
    scan_result = {"hosts": []}
    for path in output_paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[!] Could not load {path}: {e}")
            continue

        for host, hdata in data.items():
            host_entry = {"ip": host, "ports": []}
            for pstr, v in (hdata.get("ports") or {}).items():
                host_entry["ports"].append({
                    "port": int(pstr),
                    "proto": v.get("proto", "tcp"),
                    "service": v.get("name") or "",
                    "name": v.get("name") or "",
                    "product": v.get("product") or "",
                    "version": v.get("version") or "",
                    "extrainfo": v.get("extrainfo") or "",
                    "cpe": v.get("cpe") or [],
                })
            scan_result["hosts"].append(host_entry)

    # Optionally enrich with GHDB intel
    ghdb_suggestions = {}
    if ghdb_enabled and scan_result["hosts"]:
        try:
            if _suggest_from_nmap:
                ghdb_suggestions = _suggest_from_nmap(
                    scan_results=scan_result,
                    source=ghdb_source,
                    limit_per_port=ghdb_limit,
                    extra_grep=ghdb_grep,
                    debug=ghdb_debug,
                )
            else:
                ghdb_suggestions = _suggest_from_nmap_fallback(
                    scan_results=scan_result,
                    source=ghdb_source,
                    limit_per_port=ghdb_limit,
                    extra_grep=ghdb_grep,
                    debug=ghdb_debug,
                )
        except Exception as e:
            ghdb_suggestions = {"error": f"GHDB suggestion error: {e}"}

        # Console summary (top few per key)
        for key, entries in ghdb_suggestions.items():
            if key == "error":
                print(f"[GHDB] {entries}")
                continue
            print(f"\n[GHDB] Suggestions for {key}:")
            for r in entries[:min(10, ghdb_limit)]:
                t = r.get("title") or "(no title)"
                u = r.get("url") or ""
                d = (r.get("dork") or "")[:80]
                print(f"  - {t} -> {u} | dork: {d}{'…' if len(r.get('dork') or '') > 80 else ''}")

    # Final summary (optional)
    device_settings = load_device_settings()
    summary_rows = [
        (host, data.get("priority", "?"), data.get("heuristic_score", 0))
        for host, data in device_settings.items()
    ]
    print("\n[🔍 CHARLOTTE Device Priority Summary]")
    if tabulate:
        print(tabulate(sorted(summary_rows, key=lambda x: x[2], reverse=True), headers=["Host", "Priority", "Score"]))
    else:
        for row in sorted(summary_rows, key=lambda x: x[2], reverse=True):
            print(f"  {row[0]:<20} {row[1]:<6} {row[2]}")

    # Return extended structure (backward compatible: includes output_paths)
    return {
        "task": "port_scan",
        "status": "ok",
        "output_paths": output_paths,
        "results": scan_result,
        "intel": {
            "ghdb": ghdb_suggestions
        },
    }

# ──────────────────────────────────────────────────────────────────────────────
# Plugin entry point (manager-compatible)
# ──────────────────────────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────────────────────
# Plugin entry point (manager-compatible)
# ──────────────────────────────────────────────────────────────────────────────
def run_plugin(args=None, output_dir="data/findings"):
    """
    CHARLOTTE plugin entry point. Signature is manager-compatible.
    Now with optional GHDB intelligence suggestions.

    Behavior:
      - Headless chaining:
          args = {"targets": ["10.0.0.5", "10.0.0.6"], "scan_type": "-sV", "ports": "1-1024"}
      - Interactive:
          no args or no 'targets' -> show menu + prompt user
    """
    args = args or {}
    # 1) Run your existing Nmap scan logic to produce `scan_result`
    #    Ensure it has the shape described in ghdb_linker.suggest_from_nmap(...)
    #    Example skeleton:
    #
    # scan_result = {
    #   "hosts": [
    #      {"ip": "192.168.1.10",
    #       "ports": [
    #          {"port": 80, "proto": "tcp", "service": "http",
    #           "product": "Apache httpd", "version": "2.4.52",
    #           "extrainfo": "(Ubuntu)",
    #           "cpe": ["cpe:/a:apache:http_server:2.4.52"]},
    #       ]
    #      }
    #   ]
    # }

    # Delegate to the full implementation (saves results, prints summaries, GHDB intel, etc.)
    full = run_plugin_full(args=args, output_dir=output_dir)

    # Return the FULL dict so downstream code can do result.get(...)
    return full
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # When running as a script, use the full version so you see intel + summaries
    run_plugin_full()
    # For testing purposes, you can still call run_nmap_scan manually if desired:
    # run_nmap_scan(SCAN_TYPES["4"], "scanme.nmap.org", ports="22,80,443", output_dir="data/findings")
    # Note: this won't include GHDB suggestions, just raw scan results.
