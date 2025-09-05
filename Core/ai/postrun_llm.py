# core/ai/postrun_llm.py
from core.ai.llm import analyze_plugin_output, redact_for_prompt
from utils.paths import ensure_parent, display_path
from datetime import datetime


def postrun_llm(plugin_name: str, result: dict):
    # Normalize non-dict results (defensive; plugin_manager already normalizes)
    if not isinstance(result, dict):
        result = {"status": "ok", "output": str(result)}
    payload = {"plugin": plugin_name, **result}
    safe = redact_for_prompt(payload)
    md = analyze_plugin_output(plugin_name, safe)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = ensure_parent("data", "reports", f"ai_{plugin_name}_{ts}.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(md + "\n")
    print(f"[🧠 LLM Analysis saved to: {display_path(path)}]")
