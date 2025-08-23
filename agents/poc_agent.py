# ******************************************************************************************
# agents/exploit_agent.py
# Demo-ready PoC bundle generator (safe-by-default)
# - Reads triaged findings
# - Picks a scenario-aware template
# - Emits a folder per CVE with: README.md, poc.py, exploit_config.yaml, evidence.json
# ******************************************************************************************

import os
import json
import re
import time
import argparse

from datetime import datetime
from datetime import timezone
from typing import Dict, Any, List, Tuple

TRYIAGED_DEFAULT = "data/triaged_findings.json"
OUTPUT_ROOT = "reports/pocs"

# ------------------------------- Utilities -------------------------------- #

def load_triaged_findings(file_path: str = TRYIAGED_DEFAULT) -> List[Dict[str, Any]]:
    if not os.path.exists(file_path):
        print(f"[!] Triaged findings not found: {file_path}")
        return []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Error loading triaged findings: {e}")
        return []

def safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name)

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def now_utc_iso() -> str:
    
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

# ----------------------------- Heuristics --------------------------------- #

HTTP_KEYWORDS = (
    "http", "https", "web", "cookie", "csrf", "jwt", "token", "header", "request",
    "endpoint", "url", "api", "rest", "graphql", "soap", "parameter", "query"
)

SCENARIOS = {
    "web_auth_bypass_or_sqli": {
        "cwe": {"CWE-89", "CWE-287", "CWE-306", "CWE-352"},
        "hints": {"sqli", "auth", "login", "bypass", "inject"}
    },
    "file_disclosure_or_lfi": {
        "cwe": {"CWE-22", "CWE-73", "CWE-98", "CWE-59"},
        "hints": {"path traversal", "directory traversal", "lfi", "download"}
    },
    "unsafe_deserialization_rce": {
        "cwe": {"CWE-502", "CWE-94"},
        "hints": {"deserialize", "serialization", "rce", "java", "object"}
    },
    "weak_auth_or_misconfig": {
        "cwe": {"CWE-266", "CWE-284", "CWE-639"},
        "hints": {"permissions", "rbac", "acl", "insecure default", "guest"}
    },
    "generic": {
        "cwe": set(),
        "hints": set()
    }
}

def pick_scenario(vuln: Dict[str, Any]) -> str:
    text = " ".join(str(vuln.get(k, "")) for k in ("id","title","description","cwe","tags")).lower()
    cwe = str(vuln.get("cwe", "")).upper()
    for scenario, rules in SCENARIOS.items():
        if cwe in rules["cwe"]:
            return scenario
        if any(h in text for h in rules["hints"]):
            return scenario
    # fallback: if it smells like HTTP, choose auth/sqli basket for a structured web PoC
    if any(k in text for k in HTTP_KEYWORDS):
        return "web_auth_bypass_or_sqli"
    return "generic"

# ----------------------------- Templates ---------------------------------- #

DISCLAIMER = """\
# ⚠️ Ethical Use & Authorization Required
This proof-of-concept (PoC) bundle is for **authorized security testing only**.
Do not run these scripts against systems you do not own or explicitly have
written permission to test. The default script path performs **non-destructive
verification** steps. To enable any intrusive steps you must set an explicit
acknowledgement flag in the environment or CLI (see `poc.py` for details).
"""

README_TMPL = """\
# {cve_id} — {title}

**Severity/Score:** {severity} / {score}  
**Exploitability (predicted):** {prediction} ({confidence})  
**CWE:** {cwe}  
**Component/Service:** {service}  
**Detected:** {detected_at}  
**Generated:** {generated_at}

{disclaimer}

## Summary
{summary}

## Preconditions
- Target is reachable (see `exploit_config.yaml`)
- Tester has written authorization
- Optional auth token/credentials if applicable

## Contents
- `poc.py` — safe verification script with rate limiting and dry-run by default
- `exploit_config.yaml` — target URL/host, auth headers, rate limits, toggles
- `evidence.json` — (optional) artifact store used by `poc.py` for captures

## How to Run (non-destructive)
```bash
python poc.py --config exploit_config.yaml --verify-only
```
- This will run the PoC in verification mode only (no destructive actions)
- Ensure you have permission to test the target system.
"""
# This script generates proof-of-concept (PoC) templates for vulnerabilities
# that have been triaged and predicted to be exploitable. It reads from a JSON file 