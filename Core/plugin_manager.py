# ******************************************************************************************
# plugin_manager.py - Robust Plugin Loader for CHARLOTTE
#
# PURPOSE:
#   Dynamically load and execute CHARLOTTE's plugins with robust imports.
#   Avoids name collisions with third-party 'plugins' packages by falling back
#   to absolute file path imports. Handles static and dynamic plugin discovery.
#   Also supports executing "dynamic" plugins described by plugin.yaml.
#
# NOTE (what changed):
#   • Added DYNAMIC_PLUGINS global (label -> metadata) so main.py can build a menu.
#   • load_plugins() now computes & publishes that index.
#   • Added run_dynamic_by_label(label, ...) convenience wrapper.
#   • dynamic_index_by_label() now respects 'exposed: false' in plugin.yaml.
# ******************************************************************************************

import os
import sys
import yaml
import importlib
import importlib.util
import traceback
import inspect
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ──────────────────────────────────────────────────────────────────────────────
# Repo root + plugin paths
# ──────────────────────────────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

PLUGINS_DIR = ROOT_DIR / "plugins"
PLUGIN_DIR = "plugins"  # used by os.walk()

# Exposed dynamic registry (label -> metadata). Populated by load_plugins().
DYNAMIC_PLUGINS: Dict[str, Dict] = {}

# ──────────────────────────────────────────────────────────────────────────────
# Static Plugin Registry
# ──────────────────────────────────────────────────────────────────────────────
PLUGIN_REGISTRY: Dict[str, Tuple[str, str]] = {
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
    # Optional static fallback for Amass (not required if using dynamic YAML):
    # "owasp_amass": ("recon.amass", "owasp_amass"),
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
    """Try to import a module by dotted path, return None on failure."""
    try:
        return importlib.import_module(dotted)
    except Exception:
        return None


def _import_by_path(module_name: str, file_path: Path):
    """Import a module directly from a file path under a stable module name."""
    spec = importlib.util.spec_from_file_location(module_name, str(file_path))
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load spec for {module_name} from {file_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    sys.modules[module_name] = mod
    return mod


def _load_plugin_module(category: str, module: str):
    """
    Load a plugin module, supporting nested categories like 'recon.nmap'.
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
    safe_name = f"charlotte.plugins.{category}.{module}"
    return _import_by_path(safe_name, file_path)

# ──────────────────────────────────────────────────────────────────────────────
# Entrypoint dispatcher (static & dynamic share this)
# ──────────────────────────────────────────────────────────────────────────────

def _call_plugin_entrypoint(plugin_module, args: Optional[Dict] = None) -> str:
    """
    Prefer plugin.run(args) → fallback to plugin.run_plugin(args or None).
    """
    if hasattr(plugin_module, "run"):
        try:
            return plugin_module.run(args or {})
        except TypeError:
            # signature mismatch; continue to try run_plugin
            pass
    if hasattr(plugin_module, "run_plugin"):
        try:
            return plugin_module.run_plugin(args)
        except TypeError:
            # allow zero-arg run_plugin()
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
# Dynamic discovery + execution
# ──────────────────────────────────────────────────────────────────────────────

_discovery_cache: Optional[List[Dict]] = None

def discover_plugins() -> List[Dict]:
    """
    Scan plugin directories for plugin.yaml metadata files.
    Returns a list of dicts with at least: label, description, (optional) tags,
    and recommended fields such as: entry_point, function, exposed, path.
    """
    global _discovery_cache
    if _discovery_cache is not None:
        return _discovery_cache

    plugins: List[Dict] = []
    for root, _, files in os.walk(PLUGIN_DIR):
        if "plugin.yaml" in files:
            yaml_path = os.path.join(root, "plugin.yaml")
            try:
                with open(yaml_path, "r", encoding="utf-8") as f:
                    metadata = yaml.safe_load(f)
                    if not isinstance(metadata, dict):
                        continue
                    metadata["path"] = root

                    # Normalize label
                    label = metadata.get("label") or metadata.get("name")
                    if not label:
                        desc = metadata.get("description")
                        if desc:
                            label = str(desc).split(". ")[0][:40]
                        else:
                            label = os.path.basename(root)
                    metadata["label"] = label

                    # Normalize entry point/function keys (optional in YAML)
                    # Support either dotted "plugins.recon.amass.owasp_amass"
                    # or file path "plugins/recon/amass/owasp_amass.py"
                    ep = metadata.get("entry_point") or metadata.get("entrypoint") or metadata.get("module")
                    fn = metadata.get("function") or "run_plugin"
                    if ep:
                        metadata["entry_point"] = ep
                        metadata["function"] = fn

                    plugins.append(metadata)
            except Exception as e:
                print(f"[!] Failed to load plugin.yaml from {yaml_path}: {e}")

    _discovery_cache = plugins
    return plugins


def _resolve_dynamic_entry(entry_point: str):
    """
    Resolve a dynamic entry point that may be dotted or a file path.
    Returns a loaded module.
    """
    # If dotted (has dots and no path separators), try dotted import first
    if ("/" not in entry_point) and ("\\" not in entry_point):
        mod = _import_by_dotted(entry_point)
        if mod:
            return mod
        # If it looked dotted but didn't import, try translating to a path
        file_path = ROOT_DIR / (entry_point.replace(".", "/") + ".py")
        if file_path.exists():
            return _import_by_path(f"charlotte.dynamic.{file_path.stem}", file_path)
        raise ModuleNotFoundError(f"Dynamic module '{entry_point}' not found.")

    # Otherwise treat as a file path (allow relative paths under repo)
    file_path = (ROOT_DIR / entry_point).resolve() if not entry_point.startswith(str(ROOT_DIR)) else Path(entry_point)
    if not file_path.exists():
        raise FileNotFoundError(f"Dynamic plugin file not found: {file_path}")
    return _import_by_path(f"charlotte.dynamic.{file_path.stem}", file_path)


def run_dynamic(entry_point: str, function: str = "run_plugin", args: Optional[Dict] = None):
    """
    Execute a dynamic plugin specified by entry_point + function.
    `entry_point` may be dotted (e.g., "plugins.recon.amass.owasp_amass")
    or a file path (e.g., "plugins/recon/amass/owasp_amass.py").
    """
    if args is None:
        args = {}

    mod = _resolve_dynamic_entry(entry_point)

    if not hasattr(mod, function):
        raise AttributeError(f"Dynamic entry '{entry_point}' missing callable '{function}()'")

    fn = getattr(mod, function)
    # Mirror static dispatcher behavior: try with args, then zero-arg fallback
    try:
        return fn(args)
    except TypeError:
        return fn()


def run_dynamic_by_label(label: str, args: Optional[Dict] = None):
    """
    Convenience wrapper: execute a dynamic plugin by its menu label.
    Looks up entry_point/function in DYNAMIC_PLUGINS and delegates to run_dynamic().
    """
    meta = DYNAMIC_PLUGINS.get(label)
    if not meta:
        raise KeyError(f"Dynamic plugin with label '{label}' not found.")
    ep = meta.get("entry_point")
    fn = meta.get("function", "run_plugin")
    if not ep:
        raise RuntimeError(f"Dynamic plugin '{label}' is missing 'entry_point' in plugin.yaml.")
    return run_dynamic(ep, function=fn, args=args)


# Optional: convenience index for menus (key by label)
def dynamic_index_by_label() -> Dict[str, Dict]:
    """
    Return a dict mapping label -> plugin metadata for all discovered plugins.
    Respects 'exposed: false' if present in plugin.yaml.
    """
    items = discover_plugins()
    out: Dict[str, Dict] = {}
    for meta in items:
        if not isinstance(meta, dict):
            continue
        if meta.get("exposed", True) is False:
            continue
        label = meta.get("label") or meta.get("name")
        if label:
            out[str(label)] = meta
    return out

# ──────────────────────────────────────────────────────────────────────────────
# Loader / printing
# ──────────────────────────────────────────────────────────────────────────────
_plugins_loaded_banner_printed = False

def load_plugins():
    """
    Print static & dynamic plugin listings once per process (side-effect)
    and PUBLISH the dynamic label->metadata map for menu consumption.
    """
    global _plugins_loaded_banner_printed, DYNAMIC_PLUGINS
    if _plugins_loaded_banner_printed:
        return

    print("📦 Loading CHARLOTTE Plugins...")
    print("🔌 Static Plugins:")
    for key, (category, module_name) in PLUGIN_REGISTRY.items():
        cat_path = "/".join(category.split("."))
        print(f"  • {key:20s} → plugins/{cat_path}/{module_name}.py")

    # Discover dynamic plugins & print banner
    dynamic_plugins = discover_plugins()
    if dynamic_plugins:
        print("\n🧩 Dynamic Plugins:")
        # Build an index now and publish it
        DYNAMIC_PLUGINS = dynamic_index_by_label()
        for label, meta in DYNAMIC_PLUGINS.items():
            description = meta.get("description", "No description provided")
            print(f"  • {label:30s} :: {description}")
    else:
        print("\n🧩 Dynamic Plugins: none discovered")
        DYNAMIC_PLUGINS = {}

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

    # Also show the published dynamic index for sanity
    DYNAMIC_PLUGINS = dynamic_index_by_label()
    print("\n🧭 Dynamic Index:")
    for k in DYNAMIC_PLUGINS:
        print(f"  - {k}")

    print("\n✅ Plugin system initialized.")
