# ******************************************************************************************
# plugin_manager.py
# Responsible for dynamically loading and executing CHARLOTTE's plugins.
# Supports static task routing and dynamic plugin.yaml-based discovery.
# ******************************************************************************************

import importlib
import os
import traceback
import yaml
from typing import Dict, List

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
    "servicenow_setup": ("servicenow", "servicenow_setup"),  # 🛎️ Initial ServiceNow config wizard
}


# ******************************************************************************************
# Static Plugin Executor
# Dynamically loads and executes the requested plugin module from PLUGIN_REGISTRY
# ******************************************************************************************

# ******************************************************************************************
# Unified Plugin Loader (Populates internal registry from both static and dynamic sources)
# ******************************************************************************************

def load_plugins():
    """
    Loads both statically defined and dynamically discovered plugins.
    Prints a summary table of available plugins (optional).
    """
    print("📦 Loading CHARLOTTE Plugins...")

    # Load static plugins
    print("🔌 Static Plugins:")
    for key, (category, module_name) in PLUGIN_REGISTRY.items():
        print(f"  • {key:20s} → plugins/{category}/{module_name}.py")

    # Load dynamic plugins via plugin.yaml
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


def run_plugin(task: str, args: Dict) -> str:
    """
    Loads and executes a statically registered plugin.

    Args:
        task *str* = Key from PLUGIN_REGISTRY
        args *Dict* = Arguments passed to plugin's `run(args)` function

    Returns:
        *str* = Plugin output or error message
    """
    if task not in PLUGIN_REGISTRY:
        return f"[ERROR] No plugin registered for task '{task}'"

    category, module_name = PLUGIN_REGISTRY[task]
    module_path = f"plugins.{category}.{module_name}"

    try:
        plugin = importlib.import_module(module_path)
        if not hasattr(plugin, "run"):
            return f"[ERROR] Plugin '{module_name}' has no 'run(args)' function."
        return plugin.run(args)
    except Exception as e:
        return f"[PLUGIN ERROR]: {str(e)}\n{traceback.format_exc()}"

# ******************************************************************************************
# Dynamic Plugin Discovery (plugin.yaml-based)
# Supports CLI-accessible or auto-triggered extensions
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
 
# ******************************************************************************************
# End of plugin_manager.py
