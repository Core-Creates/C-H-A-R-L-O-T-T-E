---

## 🔧 Plugin `__init__.py` Guidelines

Each plugin folder (e.g., `plugins/recon/`, `plugins/exploitation/`) must include a properly structured `__init__.py`.

### Static Style (Recommended for Most CHARLOTTE Plugins)

```python
__all__ = [
    "plugin_one",
    "plugin_two",
    "plugin_three",
]

RECON_PLUGIN_PKG_VERSION = "0.1.0"  # Replace with appropriate label
```

### Dynamic Style (Optional for Auto-Discovery)

```python
import importlib
import traceback
from pathlib import Path

__all__ = []

def load_plugins():
    base_dir = Path(__file__).parent
    for file in base_dir.glob("*.py"):
        if file.name == "__init__.py":
            continue
        try:
            name = file.stem
            importlib.import_module(f"{__name__}.{name}")
            __all__.append(name)
        except Exception:
            print(f"[!] Failed to load plugin: {file.name}")
            traceback.print_exc()

load_plugins()
PLUGIN_PKG_VERSION = "0.1.0"
```

---

## 🧩 CHARLOTTE Modularity and Plugin Style Guidelines

CHARLOTTE is built to support clean, extendable plugin-based development.

### File Structure

- Each plugin lives under a meaningful folder path (e.g., `plugins/recon/nmap/`)
- Include:
  - `plugin.yaml` (for dynamic discovery)
  - Main logic file (e.g., `nmap_plugin.py`)
  - Optional helpers/utilities

### Design Principles

- Plugins should be **single-purpose** and **chainable** (e.g., recon → exploit → triage).
- Use `run(args)` or `run_plugin(args=None)` as the callable entrypoint.
- Modular helpers should go in `utils/` or submodules inside the plugin folder.

### Coding Style

- Follow `PEP8`
- Write modular functions with type hints
- Add signature-toned comments if appropriate (snark optional 😈)
- Use `output_path = display_path(path)` if outputting file paths for CHARLOTTE

---

## ✅ Example Static Plugin Init File

```python
# plugins/recon/__init__.py

__all__ = [
    "amass",
    "nmap",
    "subdomain_enum",
]

RECON_PLUGIN_PKG_VERSION = "0.1.0"
```

## ✅ Example OWASP ZAP Init File

```python
# plugins/exploitation/owasp_zap/__init__.py

__all__ = [
    "zap_scan",
    "zap_api_wrapper",
    "zap_active_scan",
    "zap_report_parser",
]

OWASP_ZAP_PLUGIN_PKG_VERSION = "0.1.0"
```