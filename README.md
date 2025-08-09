# 🧠 C.H.A.R.L.O.T.T.E.

**Cybernetic Heuristic Assistant for Recon, Logic, Offensive Tactics, Triage & Exploitation**  
A modular, AI-augmented offensive security framework — designed for autonomy, adaptability, and advanced analysis.

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
│       └─ web_scanner/
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

## 🚀 Coming Soon
- CVE matching from live scan data  
- GUI dashboard  
- Plugin wizard with YAML-based tool descriptions  
- Full offline mode with local CVE database and LLM weights
