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
    "nmap_scan": ("recon", "nmap_plugin"),                   # 📡 Nmap port scanner
    "subdomain_enum": ("recon", "owasp_amass"),              # 🌐 Subdomain enumeration using OWASP Amass
    "reverse_engineering": ("re", "symbolic_trace"),         # 🧠 Binary symbolic tracer
    "binary_strings": ("re", "bin_strings"),                 # 🔍 Strings & entropy scan
    "web_recon": ("recon", "subdomain_enum"),                # 🌐 Subdomain discovery
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
    Loads both static and dynamic plugins.
    Dynamically discovered plugins are merged into PLUGIN_REGISTRY at runtime.
    """
    print("📦 Loading CHARLOTTE Plugins...")

    # Static plugins
    print("🔌 Static Plugins:")
    for key, (category, module_name) in PLUGIN_REGISTRY.items():
        print(f"  • {key:25s} → plugins/{category}/{module_name}.py")

    # Dynamic plugins
    print("\n🧩 Dynamic Plugins:")
    dynamic_plugins = discover_plugins()
    for plugin in dynamic_plugins:
        label = plugin.get("label", f"plugin_{plugin['name']}")
        description = plugin.get("description", "No description")
        entry_point = plugin.get("entry_point")
        version = plugin.get("version", "0.1")
        author = plugin.get("author", "Unknown")

        if not entry_point:
            print(f"  ⚠️  Skipping '{label}' – No entry_point defined.")
            continue

        registry_key = label.lower().replace(" ", "_").replace("-", "_")
        if registry_key in PLUGIN_REGISTRY:
            print(f"  ⚠️  Skipping '{label}' – Conflicts with static plugin key.")
            continue

        # ✅ THIS IS WHAT WAS MISSING
        PLUGIN_REGISTRY[registry_key] = ("dynamic", entry_point)

        print(f"  • {label:25s} :: {description} (v{version} by {author})")

    print("✅ Plugin system ready.\n")
# Load all plugins at startup

# ******************************************************************************************
# Static Plugin loader
# ******************************************************************************************

def run_plugin(task: str, args: Dict = {}) -> str:
    """
    Loads and executes the requested plugin module.
    Supports both statically registered and dynamically discovered plugins.
    """
    if task not in PLUGIN_REGISTRY:
        return f"[ERROR] No plugin registered for task '{task}'"

    category, module_info = PLUGIN_REGISTRY[task]

    if category == "dynamic":
        # module_info is an entry_point string like "plugins.myplugin.module:run"
        return run_dynamic_plugin(module_info, args)

    # Static plugin: load from plugins/<category>/<module_name>.py
    try:
        module_path = f"plugins.{category}.{module_info}"
        plugin = importlib.import_module(module_path)
        if not hasattr(plugin, "run"):
            return f"[ERROR] Plugin '{module_info}' has no 'run(args)' function."
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

def run_dynamic_plugin(entry_point: str, args: Dict = {}) -> str:
    """Runs a plugin from entry_point = 'module.submodule:function' with optional args."""
    try:
        module_name, func_name = entry_point.split(":")
        module = importlib.import_module(module_name)
        func = getattr(module, func_name)
        return func(args)
    except Exception as e:
        print(f"[!] Failed to execute plugin: {e}")
        traceback.print_exc()
        return f"[PLUGIN ERROR]: {e}"


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
