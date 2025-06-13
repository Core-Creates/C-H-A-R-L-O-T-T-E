
# ******************************************************************************************
# plugin_manager.py
# Responsible for dynamically loading and executing CHARLOTTE's plugins.
# Used to dispatch tasks either from CLI or an LLM interface.
# ******************************************************************************************

import importlib
import os
import traceback
from typing import Dict

# ******************************************************************************************
# Plugin Registry
# Maps logical task names to their plugin category and filename (excluding extension).
# This enables CHARLOTTE to route tasks modularly across functionality groups.
# ******************************************************************************************

PLUGIN_REGISTRY = {
    "reverse_engineering": ("re", "symbolic_trace"),         # 🧠 Binary symbolic tracer
    "binary_strings": ("re", "bin_strings"),                 # 🔍 Strings & entropy scan
    "web_recon": ("recon", "subdomain_enum"),                # 🌐 Subdomain discovery
    "port_scan": ("recon", "port_scanner"),                  # 📡 Basic port scan
    "xss_scan": ("vulnscan", "xss_detector"),                # 🧼 Cross-site scripting test
    "sql_injection": ("vulnscan", "sql_injection"),          # 💉 SQLi vulnerability test
    "exploit_generation": ("agents", "exploit_agent"),       # 🚨 LLM-generated exploit suggestions
}

# ******************************************************************************************
# run_plugin
# Dynamically loads and executes the requested plugin module, passing user arguments.
# Handles plugin discovery, error reporting, and return output formatting.
# ******************************************************************************************
# ******************************************************************************************
# Optional Dynamic Plugin Loader (Placeholder for future expansion)
# ******************************************************************************************

def load_plugins():
    """
    Stub for plugin auto-discovery, scanning `plugins/` directory, etc.
    Currently does nothing — add your dynamic plugin loading logic here if needed.
    """
    # For now, CHARLOTTE doesn't dynamically load plugins from the filesystem.
    # This function exists for future-proofing or dynamic enumeration.
    print("🔌 CHARLOTTE: Plugin system initialized (static plugins).")

def run_plugin(task: str, args: Dict) -> str:
    """
    Loads and executes the plugin for the given task.

    Args:
        task *str* = Key for task type (must match PLUGIN_REGISTRY)
        args *Dict* = Dictionary of arguments to pass to plugin's run function

    Returns:
        *str* = Output from the plugin or detailed error if execution fails
    """
    if task not in PLUGIN_REGISTRY:
        return f"[ERROR] No plugin registered for task '{task}'"

    category, module_name = PLUGIN_REGISTRY[task]
    module_path = f"plugins.{category}.{module_name}"

    try:
        plugin = importlib.import_module(module_path)

        if not hasattr(plugin, "run"):
            return f"[ERROR] Plugin '{module_name}' has no 'run(args)' function."

        output = plugin.run(args)
        return output

    except Exception as e:
        return f"[PLUGIN ERROR]: {str(e)}\n{traceback.format_exc()}"
    
# ******************************************************************************************
# End of plugin_manager.py
