"""
plugin_manager.py

Responsible for dynamically loading and running CHARLOTTE plugins based on task names.
Supports CLI or LLM-directed routing to plugin modules.
"""

import importlib
import os
import traceback
from typing import Dict

# Plugin mapping: task name → category → filename (no extension)
PLUGIN_REGISTRY = {
    "reverse_engineering": ("re", "symbolic_trace"),
    "binary_strings": ("re", "bin_strings"),
    "web_recon": ("recon", "subdomain_enum"),
    "port_scan": ("recon", "port_scanner"),
    "xss_scan": ("vulnscan", "xss_detector"),
    "sql_injection": ("vulnscan", "sql_injection"),
    "exploit_generation": ("agents", "exploit_agent"),
}


def run_plugin(task: str, args: Dict) -> str:
    """
    Loads and executes the plugin for the given task.

    Args:
        task: The name of the task to run (must match PLUGIN_REGISTRY)
        args: Dictionary of arguments to pass to the plugin

    Returns:
        Output string or error message
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
