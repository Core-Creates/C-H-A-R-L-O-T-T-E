# 📦 CHARLOTTE Plugin `__init__.py` File Guidelines

> 🔧 **Purpose:**  
> This guide explains how to create and maintain `__init__.py` files in CHARLOTTE's plugin folders (`plugins/recon/`, `plugins/exploitation/`, etc.) to ensure proper package structure, importability, and optional plugin discovery.

---

## 🧩 Why `__init__.py` Matters

- **Package Declaration**: Tells Python to treat the folder as a package.
- **Clean Imports**: Enables imports like `from plugins.recon.nmap import nmap_plugin`.
- **Plugin Registry**: Allows plugin listing using `__all__`.
- **Optional: Auto-Discovery**: Can dynamically load plugins by file name.

---

## 🛠️ Creating a New `__init__.py`

Each plugin folder (e.g., `plugins/recon/`, `plugins/exploitation/`) must contain an `__init__.py` file.

### 🔹 Static Style (Preferred for Most CHARLOTTE Plugins)

Use when your plugin list is small or well-defined.

```python
# ******************************************************************************************
# plugins/<category>/__init__.py - Package marker for <category> plugins
# ******************************************************************************************

# PURPOSE:
# Declares this folder as a plugin package and lists available modules.
# ******************************************************************************************

__all__ = [
    "plugin_one",
    "plugin_two",
    "plugin_three",
]

<PLUGIN_CATEGORY>_PLUGIN_PKG_VERSION = "0.1.0"
```

📌 Replace:
- `<category>` with folder name (`recon`, `exploitation`, `owasp_zap`, etc.)
- `<PLUGIN_CATEGORY>` with uppercase label like `RECON`, `EXPLOITATION`, `OWASP_ZAP`

---

### 🔹 Dynamic Style (Optional for Plugin Discovery)

Use when you want automatic discovery of `.py` plugins inside the folder:

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

## ✏️ Updating `__init__.py` When Adding a New Plugin

Whenever you add a new plugin file:

1. **Static folders**:
   - Add the filename (without `.py`) to `__all__`:
     ```python
     __all__ = [
         "nmap",
         "amass",
         "new_plugin"  # 👈 Add this
     ]
     ```

2. **Dynamic folders**:
   - No update required—auto-detects any `.py` files at runtime.

---

## ✅ Best Practices

- Keep `__all__` sorted alphabetically for readability.
- Include a `<CATEGORY>_PLUGIN_PKG_VERSION` line to track schema changes.
- Use clear filenames for plugin modules (avoid dashes, start lowercase).
- Group shared logic (e.g. wrappers, utilities) in a subfolder or `_common.py`.

---

## 🧪 Example: `plugins/recon/__init__.py`

```python
__all__ = [
    "amass",
    "nmap",
    "subdomain_enum",
]

RECON_PLUGIN_PKG_VERSION = "0.1.0"
```

---

## 🧪 Example: `plugins/exploitation/owasp_zap/__init__.py`

```python
__all__ = [
    "zap_scan",
    "zap_api_wrapper",
    "zap_active_scan",
    "zap_report_parser",
]

OWASP_ZAP_PLUGIN_PKG_VERSION = "0.1.0"
```