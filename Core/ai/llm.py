# core/ai/llm.py
from __future__ import annotations

import os
import json
import textwrap
from typing import Any


# Optional: OpenAI (cloud) or Ollama (local). We'll pick whatever is available.
def _backend() -> str | None:
    if os.environ.get("OLLAMA_HOST") or os.environ.get("OLLAMA_BASE_URL"):
        return "ollama"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    return None


def _mk_prompt(plugin_name: str, payload: dict[str, Any]) -> tuple[str, str]:
    """(system, user) messages. Tune per plugin if you like."""
    system = """You are CHARLOTTE's security analyst. Be concise, accurate, and practical.
Output Markdown with sections: Findings, Likely Root Causes, Exploitability, Recommended Next Steps, Ticket Snippets."""
    user = textwrap.dedent(f"""
        Analyze this {plugin_name} output and produce a short, actionable assessment.

        REQUIREMENTS:
        - Use bullet points.
        - If evidence is sparse, say so explicitly.
        - Suggest 2–5 high-value next steps, with exact commands or tools where possible.
        - If CVEs are likely, name candidates (with rationale) but mark as 'needs verification'.

        DATA (JSON):
        {json.dumps(payload, indent=2, ensure_ascii=False)}
    """).strip()
    return system, user


def analyze_plugin_output(
    plugin_name: str,
    payload: dict[str, Any],
    *,
    model: str | None = None,
    max_tokens: int = 800,
) -> str:
    """
    Returns Markdown. Chooses OpenAI or Ollama automatically.
    Set CHARLOTTE_HEADLESS=1 to suppress printing in callers, if needed.
    """
    be = _backend()
    if not be:
        return "_LLM disabled (no OPENAI_API_KEY or OLLAMA_HOST set)._"

    system, user = _mk_prompt(plugin_name, payload)

    if be == "ollama":
        # Simple Ollama generate API
        import requests

        base = os.environ.get(
            "OLLAMA_BASE_URL", os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        )
        m = model or os.environ.get("CHARLOTTE_LLM_MODEL", "llama3")
        r = requests.post(
            f"{base}/api/generate",
            json={
                "model": m,
                "prompt": f"System:\n{system}\n\nUser:\n{user}\n",
                "stream": False,
                "options": {"num_predict": max_tokens},
            },
            timeout=120,
        )
        r.raise_for_status()
        return r.json().get("response", "").strip() or "_(empty response)_"

    # OpenAI fallback (new client API; works with most modern SDKs)
    try:
        from openai import OpenAI

        client = OpenAI()  # picks up OPENAI_API_KEY from env
        m = model or os.environ.get("CHARLOTTE_LLM_MODEL", "gpt-4o-mini")
        resp = client.chat.completions.create(
            model=m,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            max_tokens=max_tokens,
            temperature=0.2,
        )
        return resp.choices[0].message.content.strip()
    except Exception:
        # Older SDKs / environments: try legacy import path
        try:
            import openai  # type: ignore

            openai.api_key = os.environ["OPENAI_API_KEY"]
            m = model or os.environ.get("CHARLOTTE_LLM_MODEL", "gpt-4o-mini")
            resp = openai.ChatCompletion.create(
                model=m,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                max_tokens=max_tokens,
                temperature=0.2,
            )
            return resp["choices"][0]["message"]["content"].strip()
        except Exception as e2:
            return f"_LLM error: {e2}_"


def redact_for_prompt(data: dict[str, Any]) -> dict[str, Any]:
    """
    Example sanitizer: trim huge blobs, remove secrets if present.
    Extend this for your environment (cookies, tokens, creds, etc.).
    """

    def _maybe(x: Any):
        s = json.dumps(x, ensure_ascii=False)
        return s[:4000] + " …(truncated)…" if len(s) > 4000 else s

    sanitized = json.loads(_maybe(data))
    # basic redactions
    for k in list(sanitized.keys()):
        if k.lower() in {"password", "secret", "token", "api_key"}:
            sanitized[k] = "***REDACTED***"
    return sanitized
