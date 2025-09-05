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
#   • 🔔 NEW: Post-run hook support. After any plugin completes, we fire hooks with a
#            normalized payload so LLM/reporting layers can analyze results.
# ******************************************************************************************

from __future__ import annotations

import os
import sys
import yaml
import importlib
import importlib.util
import traceback
import inspect
from pathlib import Path
from typing import Any
from collections.abc import Callable

# ──────────────────────────────────────────────────────────────────────────────
# Repo root + plugin paths
# ──────────────────────────────────────────────────────────────────────────────
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

PLUGINS_DIR = ROOT_DIR / "plugins"
PLUGIN_DIR = "plugins"  # used by os.walk()

# Exposed dynamic registry (label -> metadata). Populated by load_plugins().
DYNAMIC_PLUGINS: dict[str, dict] = {}

# ──────────────────────────────────────────────────────────────────────────────
# Static Plugin Registry
# ──────────────────────────────────────────────────────────────────────────────
PLUGIN_REGISTRY: dict[str, tuple[str, str]] = {
    "reverse_engineering": ("re", "symbolic_trace"),  # 🧠 Binary symbolic tracer
    "binary_strings": ("re", "bin_strings"),  # 🔍 Strings & entropy scan
    "web_recon": ("recon", "subdomain_enum"),  # 🌐 Subdomain discovery
    "port_scan": ("recon.nmap", "nmap_plugin"),  # 📡 Basic port scan
    "xss_scan": ("vulnscan", "xss_detector"),  # 🧼 Cross-site scripting test
    "exploit_generation": (
        "agents",
        "exploit_agent",
    ),  # 🚨 LLM-generated exploit suggestions
    "triage_vulnerabilities": (
        "agents",
        "triage_agent",
    ),  # 📊 Vulnerability triage and scoring
    "report_dispatcher": (
        "report",
        "report_dispatcher",
    ),  # 📤 Report generation and dispatch
    "servicenow_setup": (
        "servicenow",
        "servicenow_setup",
    ),  # 🛎️ Initial ServiceNow config wizard
    "severity_predictor": (
        "ml",
        "predict_severity",
    ),  # 🤖 Predicts CVE severity using NN model
    "vulnscore": (
        "vulnscore",
        "vulnscore_plugin",
    ),  # ⚖️ Combines severity + exploitability
    "owasp_zap": ("exploitation.owasp_zap", "zap_plugin"),  # 🐝 OWASP ZAP integration
}

ALIASES: dict[str, str] = {
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
# 🔔 Post-run hook system (local + optional global)
# ──────────────────────────────────────────────────────────────────────────────

# Local registry (so you can register hooks even if core.hooks is not present)
_POST_RUN_HOOKS: list[Callable[[str, dict[str, Any]], None]] = []


def register_post_run(func: Callable[[str, dict[str, Any]], None]) -> None:
    """Register a function to receive (plugin_name, normalized_result) after run."""
    _POST_RUN_HOOKS.append(func)


# Optional global hook (if you created core.hooks.fire_post_run)
try:
    from core.hooks import fire_post_run as _GLOBAL_FIRE_POST_RUN  # type: ignore
except Exception:
    _GLOBAL_FIRE_POST_RUN = None  # pragma: no cover


def _normalize_for_hooks(
    plugin_name: str, result: Any, args: dict | None
) -> dict[str, Any]:
    """
    Convert diverse plugin returns into a predictable dict that hooks can read.
    - If result is already a dict, pass it through (and tuck args under 'args' if absent).
    - If it's a string/other, wrap under 'output'.
    """
    if isinstance(result, dict):
        payload = dict(result)  # shallow copy
        if "task" not in payload:
            payload["task"] = plugin_name
        if args is not None and "args" not in payload:
            payload["args"] = args
        # Best-effort status if missing and obvious error marker
        if "status" not in payload:
            text = (str(payload.get("error")) if "error" in payload else "").lower()
            payload["status"] = "error" if text else "ok"
        return payload

    # String or other non-dict response
    text = str(result)
    status = (
        "error"
        if text.strip().startswith("[ERROR") or "error" in text.lower()
        else "ok"
    )
    return {
        "task": plugin_name,
        "status": status,
        "output": text,
        "args": args or {},
    }


def _fire_post_run(plugin_name: str, raw_result: Any, args: dict | None) -> None:
    """Invoke both the optional global hook and all local hooks."""
    payload = _normalize_for_hooks(plugin_name, raw_result, args)
    # Global hook first (if present)
    if _GLOBAL_FIRE_POST_RUN:
        try:
            _GLOBAL_FIRE_POST_RUN(plugin_name, payload)
        except Exception as e:
            print(f"[hook] global post_run error: {e}")
    # Then local hooks
    for fn in list(_POST_RUN_HOOKS):
        try:
            fn(plugin_name, payload)
        except Exception as e:
            print(f"[hook] post_run error in {fn.__name__}: {e}")


# ──────────────────────────────────────────────────────────────────────────────
# Entrypoint dispatcher (static & dynamic share this)
# ──────────────────────────────────────────────────────────────────────────────


def _call_plugin_entrypoint(plugin_module, args: dict | None = None) -> Any:
    """
    Prefer plugin.run(args) → fallback to plugin.run_plugin(args or None).
    Returns whatever the plugin returns (dict, str, etc.).
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


# ──────────────────────────────────────────────────────────────────────────────
# Static plugin runner
# ──────────────────────────────────────────────────────────────────────────────


def run_plugin(task: str, args: dict | None = None) -> Any:
    resolved_task = ALIASES.get(task, task)
    if resolved_task not in PLUGIN_REGISTRY:
        return f"[ERROR] No plugin registered for task '{task}'"
    category, module_name = PLUGIN_REGISTRY[resolved_task]
    try:
        plugin_module = _load_plugin_module(category, module_name)
        result = _call_plugin_entrypoint(plugin_module, args)
        # 🔔 Fire post-run hooks with normalized payload
        _fire_post_run(resolved_task, result, args)
        return result
    except Exception as e:
        err = (
            f"[PLUGIN ERROR]: {str(e)}\n\nFull error details:\n{traceback.format_exc()}"
        )
        _fire_post_run(resolved_task, err, args)
        return err


# ──────────────────────────────────────────────────────────────────────────────
# Dynamic discovery + execution
# ──────────────────────────────────────────────────────────────────────────────

_discovery_cache: list[dict] | None = None


def discover_plugins() -> list[dict]:
    """
    Scan plugin directories for plugin.yaml metadata files.
    Returns a list of dicts with at least: label, description, (optional) tags,
    and recommended fields such as: entry_point, function, exposed, path.
    """
    global _discovery_cache
    if _discovery_cache is not None:
        return _discovery_cache

    plugins: list[dict] = []
    for root, _, files in os.walk(PLUGIN_DIR):
        if "plugin.yaml" in files:
            yaml_path = os.path.join(root, "plugin.yaml")
            try:
                with open(yaml_path, encoding="utf-8") as f:
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
                    ep = (
                        metadata.get("entry_point")
                        or metadata.get("entrypoint")
                        or metadata.get("module")
                    )
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
    # If dotted (has dots and no path separators), try dotted import first.
    if ("/" not in entry_point) and ("\\" not in entry_point):
        ep = entry_point.rstrip()
        # Allow accidental trailing '.py' in dotted form, e.g. 'plugins.recon.amass.owasp_amass.py'
        ep_noext = ep[:-3] if ep.endswith(".py") else ep
        mod = _import_by_dotted(ep_noext)
        if mod:
            return mod
        # If it looked dotted but didn't import, try translating to a path
        file_path = ROOT_DIR / (ep_noext.replace(".", "/") + ".py")
        if file_path.exists():
            return _import_by_path(f"charlotte.dynamic.{file_path.stem}", file_path)
        raise ModuleNotFoundError(f"Dynamic module '{entry_point}' not found.")

    # Otherwise treat as a file path (allow relative paths under repo)
    file_path = (
        (ROOT_DIR / entry_point).resolve()
        if not entry_point.startswith(str(ROOT_DIR))
        else Path(entry_point)
    )
    if not file_path.exists():
        raise FileNotFoundError(f"Dynamic plugin file not found: {file_path}")
    return _import_by_path(f"charlotte.dynamic.{file_path.stem}", file_path)


def run_dynamic(
    entry_point: str, function: str = "run_plugin", args: dict | None = None
):
    """
    Execute a dynamic plugin specified by entry_point + function.
    `entry_point` may be dotted (e.g., "plugins.recon.amass.owasp_amass")
    or a file path (e.g., "plugins/recon/amass/owasp_amass.py").
    """
    if args is None:
        args = {}

    mod = _resolve_dynamic_entry(entry_point)

    if not hasattr(mod, function):
        raise AttributeError(
            f"Dynamic entry '{entry_point}' missing callable '{function}()'"
        )

    fn = getattr(mod, function)
    # Mirror static dispatcher behavior: try with args, then zero-arg fallback
    try:
        result = fn(args)
    except TypeError:
        result = fn()

    # 🔔 Fire post-run hooks with normalized payload
    _fire_post_run(entry_point, result, args)
    return result


def run_dynamic_by_label(label: str, args: dict | None = None):
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
        raise RuntimeError(
            f"Dynamic plugin '{label}' is missing 'entry_point' in plugin.yaml."
        )
    result = run_dynamic(ep, function=fn, args=args)
    # 🔔 Fire again with a friendlier name (the menu label)
    _fire_post_run(label, result, args)
    return result


# Optional: convenience index for menus (key by label)
def dynamic_index_by_label() -> dict[str, dict]:
    """
    Return a dict mapping label -> plugin metadata for all discovered plugins.
    Respects 'exposed: false' if present in plugin.yaml.
    """
    items = discover_plugins()
    out: dict[str, dict] = {}
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
