# ******************************************************************************************
# plugin_manager.py - Robust Plugin Loader for CHARLOTTE
#
# PURPOSE:
#   Dynamically load and execute CHARLOTTE's plugins with robust imports.
#   Avoids name collisions with third-party 'plugins' packages by falling back
#   to absolute file path imports. Handles static and dynamic plugin discovery.
# ******************************************************************************************

import os
import sys
import yaml
import importlib
import importlib.util
import traceback
import inspect
from pathlib import Path
from typing import Dict, List, Optional

# ──────────────────────────────────────────────────────────────────────────────
# Repo root + plugin paths
# ──────────────────────────────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

PLUGINS_DIR = ROOT_DIR / "plugins"
PLUGIN_DIR = "plugins"

# ──────────────────────────────────────────────────────────────────────────────
# Static Plugin Registry
# ──────────────────────────────────────────────────────────────────────────────
PLUGIN_REGISTRY: Dict[str, tuple[str, str]] = {
    "reverse_engineering": ("re", "symbolic_trace"),
    "binary_strings": ("re", "bin_strings"),
    "web_recon": ("recon", "subdomain_enum"),
    "port_scan": ("recon.nmap", "nmap_plugin"),
    "xss_scan": ("vulnscan", "xss_detector"),
    "sql_injection": ("vulnscan", "sql_injection"),
    "exploit_generation": ("agents", "exploit_agent"),
    "triage_vulnerabilities": ("agents", "triage_agent"),
    "report_dispatcher": ("report", "report_dispatcher"),
    "Metasploit": ("exploitation", "metasploit_plugin"),
    "servicenow_setup": ("servicenow", "servicenow_setup"),
    "severity_predictor": ("ml", "predict_severity"),
    "vulnscore": ("vulnscore", "vulnscore_plugin"),
}

ALIASES: Dict[str, str] = {
    "triage_agent": "triage_vulnerabilities",
    "vulnerability_assessment": "vulnscore",
    "exploit_predictor": "severity_predictor",
}

# ──────────────────────────────────────────────────────────────────────────────
# Import helpers
# ──────────────────────────────────────────────────────────────────────────────

def _import_by_dotted(dotted: str):
    try:
        return importlib.import_module(dotted)
    except Exception:
        return None


def _import_by_path(module_name: str, file_path: Path):
    spec = importlib.util.spec_from_file_location(module_name, str(file_path))
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load spec for {module_name} from {file_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    sys.modules[module_name] = mod
    return mod


def _load_plugin_module(category: str, module: str):
    """Load a plugin module, supporting nested categories like 'recon.nmap'.
    Order: dotted import → file-path import.
    """
    # Try dotted import first (e.g., plugins.recon.nmap.nmap_plugin)
    dotted = f"plugins.{category}.{module}"
    mod = _import_by_dotted(dotted)
    if mod:
        return mod

    # Fall back to path import, allowing nested categories
    category_path = Path(*category.split("."))
    file_path = PLUGINS_DIR / category_path / f"{module}.py"
    if not file_path.exists():
        raise ModuleNotFoundError(f"Plugin file not found: {file_path}")
    return _import_by_path(f"charlotte.plugins.{category}.{module}", file_path)

    file_path = PLUGINS_DIR / category / f"{module}.py"
    if not file_path.exists():
        raise ModuleNotFoundError(f"Plugin file not found: {file_path}")
    return _import_by_path(f"charlotte.plugins.{category}.{module}", file_path)

# ──────────────────────────────────────────────────────────────────────────────
# Entrypoint dispatcher
# ──────────────────────────────────────────────────────────────────────────────

def _call_plugin_entrypoint(plugin_module, args: Optional[Dict] = None) -> str:
    if hasattr(plugin_module, "run"):
        try:
            return plugin_module.run(args or {})
        except TypeError:
            pass
    if hasattr(plugin_module, "run_plugin"):
        try:
            return plugin_module.run_plugin(args)
        except TypeError:
            return plugin_module.run_plugin()
    return "[ERROR] Plugin has neither run(args) nor run_plugin(args)."

# ──────────────────────────────────────────────────────────────────────────────
# Static plugin runner
# ──────────────────────────────────────────────────────────────────────────────

def run_plugin(task: str, args: Optional[Dict] = None) -> str:
    resolved_task = ALIASES.get(task, task)
    if resolved_task not in PLUGIN_REGISTRY:
        return f"[ERROR] No plugin registered for task '{task}'"
    category, module_name = PLUGIN_REGISTRY[resolved_task]
    try:
        plugin_module = _load_plugin_module(category, module_name)
        return _call_plugin_entrypoint(plugin_module, args)
    except Exception as e:
        return f"[PLUGIN ERROR]: {str(e)}\n{traceback.format_exc()}"

# ──────────────────────────────────────────────────────────────────────────────
# Dynamic discovery
# ──────────────────────────────────────────────────────────────────────────────
_discovery_cache: Optional[List[Dict]] = None

def discover_plugins() -> List[Dict]:
    global _discovery_cache
    if _discovery_cache is not None:
        return _discovery_cache

    plugins: List[Dict] = []
    for root, dirs, files in os.walk(PLUGIN_DIR):
        if "plugin.yaml" in files:
            yaml_path = os.path.join(root, "plugin.yaml")
            try:
                with open(yaml_path, "r", encoding="utf-8") as f:
                    metadata = yaml.safe_load(f)
                    if not isinstance(metadata, dict):
                        continue
                    metadata["path"] = root
                    label = metadata.get("label") or metadata.get("name")
                    if not label:
                        desc = metadata.get("description")
                        if desc:
                            label = str(desc).split(". ")[0][:40]
                        else:
                            label = os.path.basename(root)
                    metadata["label"] = label
                    plugins.append(metadata)
            except Exception as e:
                print(f"[!] Failed to load plugin.yaml from {yaml_path}: {e}")
    _discovery_cache = plugins
    return plugins

# ──────────────────────────────────────────────────────────────────────────────
# Loader / printing
# ──────────────────────────────────────────────────────────────────────────────
_plugins_loaded_banner_printed = False

def load_plugins():
    global _plugins_loaded_banner_printed
    if _plugins_loaded_banner_printed:
        return

    print("📦 Loading CHARLOTTE Plugins...")
    print("🔌 Static Plugins:")
    for key, (category, module_name) in PLUGIN_REGISTRY.items():
        cat_path = "/".join(category.split("."))
        print(f"  • {key:20s} → plugins/{cat_path}/{module_name}.py")

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
    _plugins_loaded_banner_printed = True

# ──────────────────────────────────────────────────────────────────────────────
# CLI Test Entry Point
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("🔌 Static Tasks:")
    for key in PLUGIN_REGISTRY:
        print(f"  - {key}")

    print("\n🧩 Discovered Plugins:")
    for item in discover_plugins():
        print(f"  - {item.get('label')} :: {item.get('description')}")

    print("\n✅ Plugin system initialized.")
