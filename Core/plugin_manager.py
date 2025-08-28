# ******************************************************************************************
# plugin_manager.py
# Responsible for dynamically loading and executing CHARLOTTE's plugins.
# Supports static task routing and dynamic plugin.yaml-based discovery.
# ******************************************************************************************

import os
import yaml
import inspect
import importlib
import traceback
from pathlib import Path
from typing import Dict, List, Optional

# ******************************************************************************************
# Public API
# Provides a unified interface for running plugins by task name or dynamic entry point.
# ******************************************************************************************
__all__ = ["run_plugin", "_call_plugin_entrypoint", "PLUGIN_REGISTRY", "ALIASES"]

# ******************************************************************************************
# Static Plugin Registry
# Maps logical task names to hardcoded plugin categories and filenames
# ******************************************************************************************

PLUGIN_REGISTRY = {
    "reverse_engineering": ("re", "symbolic_trace"),         # 🧠 Binary symbolic tracer
    "binary_strings": ("re", "bin_strings"),                 # 🔍 Strings & entropy scan
    "web_recon": ("recon", "subdomain_enum"),                # 🌐 Subdomain discovery
    "port_scan": ("recon", "nmap_plugin"),                   # 📡 Basic port scan
    "xss_scan": ("vulnscan", "xss_detector"),                # 🧼 Cross-site scripting test
    "sql_injection": ("vulnscan", "sql_injection"),          # 💉 SQLi vulnerability test
    "exploit_generation": ("agents", "exploit_agent"),       # 🚨 LLM-generated exploit suggestions
    "triage_vulnerabilities": ("agents", "triage_agent"),    # 📊 Vulnerability triage and scoring
    "report_dispatcher": ("report", "report_dispatcher"),    # 📤 Report generation and dispatch
    "Metasploit": ("exploitation", "metasploit_plugin"),     # 🦠 Metasploit RPC interface
    "servicenow_setup": ("servicenow", "servicenow_setup"),  # 🛎️ Initial ServiceNow config wizard
    "severity_predictor": ("ml", "predict_severity"),        # 🤖 Predicts CVE severity using NN model
    "vulnscore": ("vulnscore", "vulnscore_plugin"),          # ⚖️ Combines severity + exploitability
    "owasp_zap": ("exploitation.owasp_zap", "zap_plugin")    # 🐝 OWASP ZAP integration
}

# ******************************************************************************************
# Aliases (menu labels -> registry keys)
# Add entries whenever main.py’s PLUGIN_TASKS uses a label that differs from the registry key.
# ******************************************************************************************
ALIASES: Dict[str, str] = {
    # From main.py menu
    "triage_agent": "triage_vulnerabilities",   # 🧮 Vulnerability Triage
    "vulnerability_assessment": "vulnscore",    # 📊 Vulnerability Assessment
    "exploit_predictor": "severity_predictor",  # 🧨 Predict Exploitability
    # Add more here as you expand PLUGIN_TASKS
}

def _call_plugin_entrypoint(plugin_module, args: Optional[Dict]) -> str:
    """
    Prefer plugin.run(args) if available; otherwise try plugin.run_plugin(args=None).
    Falls back gracefully based on function signatures.
    """
    try:
        # 1) Preferred: run(args)
        if hasattr(plugin_module, "run"):
            run_fn = getattr(plugin_module, "run")
            sig = inspect.signature(run_fn)
            if len(sig.parameters) == 0:
                return run_fn()
            return run_fn(args if args is not None else {})

        # 2) Fallback: run_plugin(args=None)
        if hasattr(plugin_module, "run_plugin"):
            runp = getattr(plugin_module, "run_plugin")
            sig = inspect.signature(runp)
            if len(sig.parameters) == 0:
                return runp()
            return runp(args if args is not None else None)

        # Neither entrypoint found
        return "[ERROR] Plugin has neither run(args) nor run_plugin(args)."
    except Exception as e:
        return f"[PLUGIN EXECUTION ERROR] Failed to execute plugin entrypoint: {str(e)}\n\nFull error details:\n{traceback.format_exc()}"

# ******************************************************************************************
# Static Plugin Executor
# Dynamically loads and executes the requested plugin module from PLUGIN_REGISTRY
# ******************************************************************************************

def run_plugin(task: str, args: Optional[Dict] = None) -> str:
    """
    Loads and executes a statically registered plugin with:
      • alias resolution (menu key → registry key)
      • flexible entrypoint support (run(args) or run_plugin(args=None))

    Args:
        task: Menu/registry key for the plugin
        args: Arguments passed to the plugin (dict or None)

    Returns:
        Plugin output or error string.
    """
    # Resolve menu → registry alias, if any
    resolved_task = ALIASES.get(task, task)

    if resolved_task not in PLUGIN_REGISTRY:
        return f"[ERROR] No plugin registered for task '{task}'"

    category, module_name = PLUGIN_REGISTRY[resolved_task]
    module_path = f"plugins.{category}.{module_name}"

    try:
        plugin_module = importlib.import_module(module_path)

        # Prefer run(args) and gracefully fallback to flexible dispatcher on mismatch
        if hasattr(plugin_module, "run"):
            try:
                return plugin_module.run(args if args is not None else {})
            except TypeError:
                pass  # signature mismatch → try flexible dispatcher

        # Flexible dispatcher handles run/run_plugin variants
        return _call_plugin_entrypoint(plugin_module, args)

    except ImportError as e:
        return f"[PLUGIN ERROR] Failed to import module '{module_path}': {str(e)}\n\nThis usually means:\n- The plugin file doesn't exist\n- There's a syntax error in the plugin\n- Missing dependencies\n\nFull error: {traceback.format_exc()}"
    except Exception as e:
        return f"[PLUGIN ERROR]: {str(e)}\n\nFull error details:\n{traceback.format_exc()}"

# ******************************************************************************************
# Unified Plugin Loader (Populates internal registry from both static and dynamic sources)
# ******************************************************************************************

def load_plugins():
    """Prints all available static and dynamic plugins."""
    print("📦 Loading CHARLOTTE Plugins...")

    print("🔌 Static Plugins:")
    for key, (category, module_name) in PLUGIN_REGISTRY.items():
        print(f"  • {key:20s} → plugins/{category}/{module_name}.py")

    dynamic_plugins = discover_plugins()
    if dynamic_plugins:
        print("\n🧩 Dynamic Plugins:")
        for plugin in dynamic_plugins:
            label = plugin.get("label", "Unnamed Plugin")
            description = plugin.get("description", "No description provided")
            print(f"  • {label:30s} :: {description}")
    else:
        print("⚠️  No dynamic plugins found.")

    print("✅ Plugin system ready.\n")

# ******************************************************************************************
# Dynamic Plugin Discovery
# ******************************************************************************************

PLUGIN_DIR = "plugins"

def discover_plugins() -> List[Dict]:
    """Scans plugin directories for plugin.yaml files and loads metadata."""
    plugins = []
    for folder in os.listdir(PLUGIN_DIR):
        plugin_path = os.path.join(PLUGIN_DIR, folder)
        yaml_path = os.path.join(plugin_path, "plugin.yaml")
        if os.path.isdir(plugin_path) and os.path.isfile(yaml_path):
            try:
                with open(yaml_path, "r", encoding="utf-8") as f:
                    metadata = yaml.safe_load(f)
                    metadata["path"] = plugin_path
                    metadata["name"] = folder
                    plugins.append(metadata)
            except Exception as e:
                print(f"[!] Failed to load plugin.yaml from {folder}: {e}")
    return plugins

def run_dynamic_plugin(entry_point: str):
    """Runs a plugin from entry_point = 'module.submodule:function'."""
    try:
        module_name, func_name = entry_point.split(":")
        module = importlib.import_module(module_name)
        func = getattr(module, func_name)
        return func()
    except Exception as e:
        print(f"[!] Failed to execute plugin: {e}")
        traceback.print_exc()

def list_plugins() -> List[str]:
    """Returns a list of plugin labels and descriptions."""
    return [f"{p.get('label')} :: {p.get('description')}" for p in discover_plugins()]

def select_plugin_by_label(label: str):
    """Finds and runs a plugin by human-friendly label."""
    for plugin in discover_plugins():
        if plugin.get("label") == label:
            return run_dynamic_plugin(plugin["entry_point"])
    print(f"[!] No plugin found with label: {label}")

# ******************************************************************************************
# Optional: CLI Test Entry Point
# ******************************************************************************************

if __name__ == "__main__":
    print("🔌 Static Tasks:")
    for key in PLUGIN_REGISTRY:
        print(f"  - {key}")

    print("\n🧩 Discovered Plugins:")
    for item in list_plugins():
        print(f"  - {item}")
    print("\n✅ Plugin system initialized.")
# ******************************************************************************************
# End of plugin_manager.py