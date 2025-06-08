# 🧠 C.H.A.R.L.O.T.T.E.

**Cybernetic Heuristic Assistant for Recon, Logic, Offensive Tactics, Triage & Exploitation**  
A modular, AI-augmented offensive security framework — designed for autonomy, adaptability, and advanced analysis.

> **🛠️ 100% Open Source. Toggle between self-contained or LLM-augmented operation.**

---

## 🔍 Purpose

CHARLOTTE is built for multi-phase offensive security tasks, enabling both manual and automated workflows:

- **Recon** – Subdomain enumeration, port scanning, passive intel gathering  
- **Logic** – LLM-powered reasoning, prompt routing, symbolic analysis  
- **Offensive Tactics** – Payload crafting, fuzzing, exploit generation  
- **Triage** – Auto-ranking vulnerabilities, CVSS prediction, clustering  
- **Exploitation** – Proof-of-concept generation, post-exploitation handling  
- **Reverse Engineering** – Binary dissection, deobfuscation, symbolic tracing

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
├── core/
│   ├── llm_interface.py    # Routes prompts to local or remote LLMs
│   ├── plugin_manager.py   # Loads plugins dynamically
│   ├── config.py           # Toggles self-contained/extended modes
│   ├── cve_lookup.py       # CVE scanner (local DB or online API)
│   ├── reverse_engineer.py # Binary analysis logic (symbolic, static)
│   └── main.py             # Entry point logic + CLI control
│
├── plugins/
│   ├── recon/              # Subdomain enum, port scans, etc.
│   ├── vulnscan/           # XSS, SQLi detectors, etc.
│   ├── re/                 # Binary plugins: strings, ghidra, symbolic tracing
│
├── data/
│   ├── findings.json       # Stores scan output & metadata
│   └── fingerprints/       # Known vuln/function patterns
│
├── agents/
│   ├── exploit_agent.py    # POC generator based on findings
│   └── triage_agent.py     # Ranks issues using scoring or LLM
│
├── utils/
│   ├── logger.py           # Logging setup
│   └── filetools.py        # File/directory helpers
│
|
└── personality_config.json   ← CHARLOTTE's saved mode lives here
├── cli.py                  # CLI interface for scans, tasks, queries
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
