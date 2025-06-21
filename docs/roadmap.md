# 🗺️ CHARLOTTE Project Roadmap

Welcome to the official roadmap for **C-H-A-R-L-O-T-T-E** — our haunted, LLM-powered reverse engineering and security assistant with an attitude. This document outlines current goals, upcoming features, and long-term ambitions. Feel free to open issues or PRs tied to any item here!

---

## 🧱 Phase 1: Core Architecture (✅ In Progress)
- [x] Modular plugin system for task routing  
- [x] CLI interface with interactive menu  
- [x] Local model fallback via Hugging Face transformers  
- [x] Reverse engineering plugin scaffolding  
- [x] Runtime analysis framework  

---

## 🧩 Phase 2: Plugin Ecosystem (🔄 Active Development)
- [ ] **ThreatMapper Integration**  
  - Parse API output from ThreatMapper  
  - Enrich CHARLOTTE's triage using runtime context and cloud misconfigurations  
  - Support both agent-based and agentless deployments  
- [ ] **Binary Ninja / Ghidra Plugin**  
  - Symbolic tracing and basic decompilation  
  - Export CFG, instruction summaries, function signatures  
- [ ] **Secrets/Leak Scanner Plugin**  
  - Detect and categorize exposed secrets in repos or memory dumps  
- [ ] **CTF Toolkit Plugin**  
  - Automate solving simple reversing, crypto, or pwn challenges  

---

## 🧠 Phase 3: LLM & Prompt Engineering
- [ ] Unified `llm_interface.py` to manage model routing (local vs. remote)  
- [ ] Secure prompt injection handling  
- [ ] Prompt libraries for:  
  - Vulnerability explanation  
  - Malware triage summary  
  - Disassembler annotation assistance  

---

## 🔐 Phase 4: Security Posture Assessment
- [ ] Merge ThreatMapper signals with local scan context  
- [ ] Exploitability scoring using eBPF runtime data  
- [ ] CSPM + CWPP scoring summary per asset/container  
- [ ] **Fortinet Security Fabric Integration** *(Planned Q3–Q4 2025)*  
  - Design plugin architecture compatible with Fabric Connectors and APIs  
  - Integrate with FortiGuard and FortiAnalyzer for threat intel enrichment  
  - Support event correlation from FortiSIEM/FortiSOAR  
  - Optional: sandbox detonation via FortiSandbox API  
  - Explore submission to Fabric-Ready Technology Alliance Program  

---

## 📦 Phase 5: Packaging and Community
- [ ] Dockerized deployment  
- [ ] GitHub Actions for testing plugins  
- [ ] Contributor CLI scaffolding (`charlotte plugin create`)  
- [ ] CHARLOTTE CLI personalization (theme, sarcasm level, verbosity)  

---

## 🧪 Stretch Goals
- [ ] Discord/Slack bot mode  
- [ ] GUI dashboard (React-based or TUI)  
- [ ] Integration with Volatility for memory forensics  
- [ ] Integration with OSQuery or Sysmon logs  
- [ ] **Fortinet Ecosystem Expansion**  
  - Fetch IOCs and telemetry from additional Fabric-Ready partners  
  - Cross-correlate with Deepfence scan results for multi-vendor insights  

---

Want to help with any of these? Check out the [`good first issue`](https://github.com/your-repo/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) label or drop into a discussion to chat!

🖤 With love from CHARLOTTE (and her humans)
