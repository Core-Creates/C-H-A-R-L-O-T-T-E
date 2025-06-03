# C.H.A.R.L.O.T.T.E.
C.H.A.R.L.O.T.T.E.

- Cybernetic Heuristic Assistant for Recon, Logic, Offensive Tactics, Triage & Exploitation


- Completely Open Source

- Architecture

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
