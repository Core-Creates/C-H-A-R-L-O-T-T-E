# C.H.A.R.L.O.T.T.E.

**Cybernetic Heuristic Assistant for Recon, Logic, Offensive Tactics, Triage & Exploitation**

---

> **Completely Open Source**

---

### 🧠 Purpose

Cybernetic Heuristic Assistant for:

- **Recon** → Web reconnaissance, scanning, passive intel gathering  
- **Logic** → LLM reasoning, prompt routing, static/dynamic analysis  
- **Offensive Tactics** → Exploit suggestion, payload crafting, fuzzing  
- **Triage** → Auto-prioritizing vulnerabilities, CVSS estimation  
- **Exploitation** → Proof-of-concept generator, post-exploitation notes  
- **Reverse Engineering** → Binary analysis, function extraction, deobfuscation, symbolic tracing  

---

### 📁 Folder Structure

```plaintext
charlotte/
├── core/
│   ├── llm_interface.py        # Handles prompt routing, OpenAI/HF API, etc.
│   ├── plugin_manager.py       # Dynamically loads tools and scripts
│   ├── config.py               # Global settings, API keys, etc.
│
├── plugins/
│   ├── recon/
│   │   ├── subdomain_enum.py   # Passive + active recon
│   │   ├── port_scanner.py     # Nmap or socket scanner
│   │
│   ├── vulnscan/
│   │   ├── sql_injection.py
│   │   ├── xss_detector.py
│   │
│   ├── re/
│   │   ├── bin_strings.py      # Strings + entropy analyzer
│   │   ├── ghidra_bridge.py    # Interact with Ghidra headless mode
│   │   ├── symbolic_trace.py   # (for deobfuscation or tracing)
│
├── data/
│   ├── findings.json           # Stores parsed scan results
│   ├── fingerprints/           # Known vuln fingerprints
│
├── agents/
│   ├── exploit_agent.py        # Uses results + reasoning to generate POCs
│   ├── triage_agent.py         # Ranks issues using LLM
│
├── utils/
│   ├── logger.py
│   ├── filetools.py
│
├── cli.py                      # CLI wrapper to run scans or ask questions
└── README.md                   # About C.H.A.R.L.O.T.T.E.

               ┌────────────────────────────┐
               │        Charlotte           │
               │  LLM-Driven Assistant Core │
               └────────────┬───────────────┘
                            │
      ┌─────────────────────┼─────────────────────┐
      ▼                     ▼                     ▼
┌────────────┐       ┌──────────────┐       ┌─────────────┐
│ VulnScanner│       │ RE Assistant │       │ Prompt Engine│
│ (Web Vulns)│       │ (Bin Analysis│       │  (LLM Logic) │
└────┬───────┘       └──────┬───────┘       └──────┬───────┘
     │                      │                     │
     ▼                      ▼                     ▼
┌─────────────┐      ┌─────────────┐       ┌────────────────┐
│ ZAP/Burp API│      │ Ghidra API  │       │ Retrieval +    │
│ or custom   │      │ or BinaryNinja│     │ Tool Plugins   │
│ scanner     │      │ scripting    │      │ (LLMs, tools)  │
└─────────────┘      └─────────────┘       └────────────────┘
