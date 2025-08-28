# 🧠 C.H.A.R.L.O.T.T.E.

**Cybernetic Heuristic Assistant for Recon, Logic, Offensive Tactics, Triage & Exploitation**  
A modular, AI-augmented offensive and defensive security framework — designed for autonomy, adaptability, and advanced analysis.

> **🛠️ 100% Open Source. Toggle between self-contained or LLM-augmented operation.**

---

## 🔍 Purpose

CHARLOTTE is built for multi-phase defensive and offensive security tasks, enabling both manual and automated workflows:

- **Recon** – Subdomain enumeration, port scanning, passive intel gathering  
- **Logic** – LLM-powered reasoning, prompt routing, symbolic analysis  
- **Offensive Tactics** – Payload crafting, fuzzing, exploit generation  
- **Triage** – Auto-ranking vulnerabilities, CVSS prediction, clustering  
- **Exploitation** – Proof-of-concept generation, post-exploitation handling  
- **Reverse Engineering** – Binary dissection, deobfuscation, symbolic tracing

---
website:
## https://www.c-h-a-r-l-o-t-t-e.org/

---

## 🧬 Dual Intelligence Modes

CHARLOTTE can operate in one of two modes:

| Mode               | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| **Self-Contained** | Runs fully offline using embedded models and logic                          |
| **Extended**       | Utilizes remote APIs (OpenAI, HuggingFace, etc.) for enhanced capabilities |

Toggle the mode easily via `config.py` or runtime CLI flag.

---

## 🗂️ Folder Structure

```plaintext
charlotte/
├── agents/
│   ├── exploit_agent.py    # POC generator based on findings
│   └── triage_agent.py     # Ranks issues using scoring or LLM
├── core/
│   ├── integrations/
│   │   └── burp_integration.py
│   ├── logic_modules/
│   │   ├── exploit_predictor.py
│   │   ├── recon_heuristics.py
│   │   ├── report_utils.py
│   │   └── triage_rules.py
│   ├── charlotte_personality.py # Toggles self-contained/extended modes
│   ├── code_reasoner.py    # LLM-powered reasoning
│   ├── config.py           # Configuration and mode toggling
│   ├── cve_lookup.py       # CVE scanner (local DB or online API)
│   ├── data_loader.py
│   ├── llm_interface.py    # Routes prompts to local or remote LLMs
│   ├── main.py             # Entry point logic + CLI control
│   ├── plugin_manager.py   # Loads plugins dynamically
│   ├── report_dispatcher.py
│   ├── reverse_engineer.py # Binary analysis logic (symbolic, static)
│   └── user_config.py
|
├── data/
│   ├── findings.json       # Stores scan output & metadata
│   ├── fingerprints/       # Known vuln/function patterns
|   ├── parsed
|   |    ├── charlotte_features.csv     ← Feature-only CSV
|   |    ├── charlotte_labels.csv       ← Label-only CSV
|   |    └── charlotte_dataset.csv      ← Combined for training
|   |
│   └── model_weights/
│       ├── severity_net.pt
│       └── scaler_severity.pkl
│
|
|
├── installer
|   ├── ghidra
|   |   ├── ghidra_installer.ps1
│   |   ├── ghidra_installer.py
|   |   └── ghidra_installer.sh
|   |
|   |
│   └── binary_ninja
│
├── plugins/
│   |── servicenow/
│   |   ├── servicenow_client.py        # Handles auth and incident creation
│   |   ├── servicenow_setup.py         # One-time config wizard
|   |   └── plugin.yaml
|   |
|   |
│   |── re/                 # Binary plugins: strings, ghidra, symbolic tracing
│   |   ├── bin_strings.py  # 🔍 String & entropy analysis plugin
│   |   ├── symbolic_trace.py 
│   |   └── ghidra_bridge.py 
|   |
|   |
│   |── recon/              # Subdomain enum, port scans, etc.
│   |   ├── amass/
│   |   │   ├── owasp_amass.py   # OWASP Amass plugin
│   |   │   └── plugin.yaml
│   |   ├── http_banner/
│   |   │   ├── http_banner.py   # HTTP banner grabber plugin
│   |   │   └── plugin.yaml
│   |   ├── nmap
|   |   |   ├── nmap_plugin.py       # Nmap plugin
|   |   |   └── plugin.yaml
|   |   |
│   |   └── (other recon plugins)
|   |
│   ├── vulnscan/           # XSS, SQLi detectors, etc.
│       ├── nessus_plugin.py
│       ├──web_scanner/
│           └─ burp_suite_plugin.py     # Pure Python scanner
|
|
|
├── poc_templates/         # <-- 🧠 stays here (root-level directory, sibling to core/)
│   ├── CWE-77_Command_Injection.py
│   ├── CWE-119_Buffer_Overflow.py
│   └──   
|
├─ scripts/
|  ├── __init__.py
│  ├── cache_model.py  
│  ├── launch_burp_service.sh
|  └── train_severity_model.py
|
├─ tests
│   ├── test_CVESeverityNet.py
│   ├── test_report_utils.py
|
├── utils/
|   ├── __init__.py
│   ├── load_nmap_results.py
│   ├── logger.py           # Logging setup
│   ├── file_tools.py        # File/directory helpers
|   ├── parse_cvrf.py
|   ├── parse_json.py
│   └── utils.py
|
│
|
├─ build.gradle
├── cli.py                  # CLI interface for scans, tasks, queries
├── personality_config.json   ← CHARLOTTE's saved mode lives here
├─ settings.gradle
└── README.md
```

---

## 🧩 System Overview

```
               ┌────────────────────────────┐
               │        CHARLOTTE           │
               │  LLM-Driven Assistant Core │
               └────────────┬───────────────┘
                            │
      ┌─────────────────────┼─────────────────────┐
      ▼                     ▼                     ▼
┌────────────┐       ┌───────────────┐      ┌──────────────┐
│ VulnScanner│       │ RE Assistant  │      │ Prompt Engine│
│ (Web Vulns)│       │ (Bin Analysis)│      │  (LLM Logic) │
└────┬───────┘       └──────┬────────┘      └──────┬───────┘
     │                      │                     │
     ▼                      ▼                     ▼
┌─────────────┐      ┌─────────────┐       ┌────────────────┐
│ ZAP/Burp API│      │ Ghidra API  │       │ Retrieval +    │
│ or Custom   │      │ or BinNinja │       │ Tool Plugins   │
│ Scanner     │      │ Headless RE │       │ (LLMs, local)  │
└─────────────┘      └─────────────┘       └────────────────┘
```

---

## 🧩 Plugin System

CHARLOTTE uses a flexible plugin system supporting both statically registered and dynamically discovered plugins for easy extension and modularity.

### Plugin Flow

1. **Static Plugins**
   - Registered in `core/plugin_manager.py` via the `PLUGIN_REGISTRY` dictionary.
   - Each entry maps a logical task name to a plugin module (e.g., `("re", "symbolic_trace")`).
   - Aliases in `ALIASES` allow menu labels to map to registry keys.
   - The `run_plugin(task, args)` function loads and executes the plugin, preferring a `run(args)` entrypoint, with fallbacks.

2. **Dynamic Plugins**
   - Discovered by scanning subdirectories in the `plugins/` folder for a `plugin.yaml` file.
   - Metadata (label, description, entry_point) is loaded from `plugin.yaml`.
   - The `run_dynamic_plugin(entry_point)` function loads and runs the specified function (e.g., `module.submodule:function`).

3. **Unified Loader**
   - `load_plugins()` prints all available static and dynamic plugins for visibility.

### File Structure

- `core/plugin_manager.py`: Main logic for plugin registration, loading, and execution.
- `plugins/`: Directory containing plugin subfolders.
  - Each static plugin is a Python module (e.g., `plugins/re/symbolic_trace.py`).
  - Each dynamic plugin has a `plugin.yaml` and its code.

### Creating a New Plugin

#### Static Plugin

1. Add your plugin module under the appropriate subdirectory in `plugins/`.
2. Implement a `run(args)` or `run_plugin(args=None)` function.
3. Register your plugin in `PLUGIN_REGISTRY` in `core/plugin_manager.py`.
4. (Optional) Add an alias in `ALIASES` if needed.

#### Dynamic Plugin

1. Create a new subdirectory in `plugins/`.
2. Add your plugin code and a `plugin.yaml` with metadata:
   ```yaml
   label: My Plugin
   description: Does something useful
   entry_point: plugins.my_plugin.module:function
   ```
   
---

## Separation of Ownership
```

                 🎓 C-H-A-R-L-O-T-T-E (501(c)(3))
   ─────────────────────────────────────────────────────────────
   • Owns IP of CHARLOTTE OSS
   • Distributes core under AGPLv3
   • Manages community, grants, contributors
   • Contributors sign CLA (allows relicensing)

                     │
                     │ Dual-License Authority
                     ▼
                 💼 C-H-A-R-L-O-T-T-E Corp (C-Corp)
   ─────────────────────────────────────────────────────────────
   • Sells proprietary enterprise licenses
   • Provides commercial support, SLAs
   • Can develop proprietary add-ons
   • Revenues help sustain Foundation mission
```
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
    "zap_plugin",
]

OWASP_ZAP_PLUGIN_PKG_VERSION = "0.1.0"
```
---

## 🚀 Coming Soon 
- GUI dashboard   
- Full offline mode with local CVE database and LLM weights
- Self-Patching agents that can patch their hosts

---