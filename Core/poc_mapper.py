
# ******************************************************************************************
# core/poc_mapper.py
# Dynamically maps triaged findings to appropriate PoC templates and executes them
# ******************************************************************************************

import importlib.util
import os

TEMPLATE_DIR = "poc_templates"

# Maps CWE keywords to PoC template filenames (can be expanded)
CWE_MAP = {
    "xss": "CWE-79_Cross-Site_Scripting_(XSS).py",
    "sql injection": "CWE-89_SQL_Injection.py",
}

def match_template(cwe_str):
    cwe_lower = cwe_str.lower()
    for keyword, template in CWE_MAP.items():
        if keyword in cwe_lower:
            return os.path.join(TEMPLATE_DIR, template)
    return None

def run_dynamic_poc(finding):
    cwe = finding.get("cwe", "")
    template_path = match_template(cwe)
    if not template_path or not os.path.exists(template_path):
        print(f"[!] No PoC template found for CWE: {cwe}")
        return

    # Dynamically load the template as a module
    spec = importlib.util.spec_from_file_location("poc_module", template_path)
    poc_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(poc_module)

    # Look for the PoC function in the module and run it
    for attr in dir(poc_module):
        if attr.startswith("run_") and callable(getattr(poc_module, attr)):
            print(f"[*] Running {attr}() for {finding.get('id', 'Unknown CVE')}...")
            getattr(poc_module, attr)(finding)
            break
    else:
        print("[!] No run_* function found in template.")

