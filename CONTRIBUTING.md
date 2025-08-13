# 🤝 Contributing to C-H-A-R-L-O-T-T-E

Welcome! 👋 We’re thrilled you’re interested in contributing to **C-H-A-R-L-O-T-T-E**, our chaotic-neutral, brooding, reverse-engineering-savvy security assistant. Whether you're into plugin development, LLM integration, binary analysis, or just want to squash bugs — there's a place for you here.

## 🧠 What Is CHARLOTTE?
CHARLOTTE is a modular AI assistant built to assist in:
- Reverse engineering of binaries
- Symbolic execution and malware analysis
- Hybrid cloud & on-premise infrastructure assessments
- Integrating with tools like Deepfence ThreatMapper

## 🛠️ Getting Started


1. **Fork the Repo**
   - Click the “Fork” button at the top right of the repository.


*Make on your computer or in CodeSpaces*
---
## 2 below are how to setup a codespace in your browser
*Ignore if wanting to download and run directly on computer*
2. **Setup Code Space**
   - click the code button on the github page
   - select code spaces
   - then click on the codespace that is setup

## OR

---

2. **Clone Your Fork**
   ```bash
   git clone https://github.com/<your-username>/C-H-A-R-L-O-T-T-E.git
   cd C-H-A-R-L-O-T-T-E
   ```
3. **🌀 Create and Activate Virtual Environment**
   From your CHARLOTTE project root:

   ```bash
   python -m venv .venv
   ```
   .venv\Scripts\activate  # Windows
   source .venv/bin/activate  # macOS/Linux


4. **Install Dependencies**
   Make sure you have Python 3.11 installed. Then:
   ```bash
   pip install -r requirements.txt
   ```

5. **Run CHARLOTTE Locally**
   ```bash
   python charlotte
   ```
6. **Set Upstream Repo to main repo"
   ```bash
   git init
   git add .
   git commit -m "first commit"
   git remote add origin https://github.com/Core-Creates/C-H-A-R-L-O-T-T-E.git
   git push -u origin master
   ```

   **Special Note if using Docker**
   ## 🐳 Running with Docker Compose

   ```bash
   docker-compose run charlotte
   ```

6. **Explore the Code**
   Key folders:
   - `core/`: Core logic and decision engine
   - `plugins/`: Modular tasks CHARLOTTE can perform (e.g., disassemblers, analyzers)
   - `llm_interface/`: Code for LLM fallback and prompt routing
   - `config/`: Project settings and credentials
   - `scripts/`: Setup and maintenance tools

## 🧩 Ways to Contribute

- 🐞 Bug fixes
- 🔌 Create a plugin (e.g., Binary Ninja, Radare2, etc.)
- 🧠 Improve symbolic tracing or exploit scoring logic
- 🤖 Expand LLM interface and prompt routing
- ☁️ Integrate with CNAPP tools like ThreatMapper
- 📄 Improve documentation or add examples

## 🧪 Running Tests

```bash
pytest tests/
```

We're working on increasing test coverage — feel free to help with that too!

## ✍️ Code Style

- Follow [PEP8](https://www.python.org/dev/peps/pep-0008/)  
- Use descriptive commit messages (`feat:`, `fix:`, `refactor:` etc.)
- Please add code blocks to break up certain sections of code example
   in the main.py use *** or ===
- Add comments in CHARLOTTE's signature tone if you're brave 😈

## 🧵 Branching Strategy

- Create a feature branch from `main`:
  ```bash
  git checkout -b feat/your-feature-name
  ```
- Submit a Pull Request with a clear description.
- Link the issue you're resolving in the PR (e.g., `Closes #42`).

## 💬 Need Help?

- Open an issue (https://github.com/users/Core-Creates/projects/2/views/1)
- Send a haunted whisper to the maintainers via discord
- Or whisper your message to the void... CHARLOTTE might answer 🖤

---

Thanks for helping CHARLOTTE grow her power. She’s watching — and appreciates your contribution. 🖤
