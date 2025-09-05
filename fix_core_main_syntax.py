#!/usr/bin/env python3
"""
Auto-fix common merge artifacts in Core/main.py introduced by automated edits.

What it does safely:
1) Normalize the core.plugin_manager import tuple (removes stray comma lines).
2) Ensure `__all__ = [...]` lives AFTER the try/except import block, with plain quotes.
3) Replace escaped quotes (\" → ") in a few targeted places (dict literals & prints).
4) Fix broken multi-line f-string prints introduced by text merges.
5) Make OWASP ZAP cancel message use normal quotes.
6) Ensure generic static plugin "Running plugin" print is a single line.

Run:
    python fix_core_main_syntax.py
"""

from __future__ import annotations
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[0]
target = ROOT.parent / "Core" / "main.py"

if not target.exists():
    print(f"[!] Could not find {target}. Adjust path in script if needed.")
    sys.exit(1)

txt = target.read_text(encoding="utf-8")

orig = txt


# 1) Normalize the plugin_manager import tuple inside the big try: block.
def fix_manager_imports(s: str) -> str:
    # Match a try: ... from core.plugin_manager import ( ... ) ... except ModuleNotFoundError
    # We only rewrite the import tuple contents; keep surrounding code untouched.
    pat = re.compile(
        r"(try:\s*\n\s*from\s+core\.plugin_manager\s+import\s*\(\s*)(?P<body>[\s\S]*?)(\s*\)\s*\n)",
        re.MULTILINE,
    )
    desired = (
        "        run_plugin,\n"
        "        _call_plugin_entrypoint,\n"
        "        register_post_run,\n"
        "        run_dynamic_by_label,\n"
        "        dynamic_index_by_label,\n"
        "        PLUGIN_REGISTRY,\n"
        "        ALIASES,\n"
    )

    def repl(m):
        before = m.group(1)
        after = m.group(3)
        return before + desired + after

    s2, n = pat.subn(repl, s, count=1)

    # Remove any accidental lone-comma line inside that tuple (defensive)
    s2 = re.sub(r"\n\s*,\s*\n", "\n", s2)
    return s2


txt = fix_manager_imports(txt)

# 2) Move __all__ to after the try/except. First, remove any \-escaped quotes.
txt = txt.replace(
    r"__all__ = [\"run_plugin\", \"_call_plugin_entrypoint\", \"PLUGIN_REGISTRY\", \"ALIASES\"]",
    '__all__ = ["run_plugin", "_call_plugin_entrypoint", "PLUGIN_REGISTRY", "ALIASES"]',
)

# Find the end of the try/except block that handles imports.
m_try = re.search(
    r"try:\s*\n[\s\S]*?\nexcept\s+ModuleNotFoundError\s+as\s+e:\s*\n[\s\S]*?\n\s*raise\s*\n",
    txt,
)
if m_try:
    # Remove any existing __all__ near the top to avoid duplicates
    txt = re.sub(r"\n__all__\s*=\s*\[[^\]]*\]\s*\n", "\n", txt, count=1)
    insert_at = m_try.end()
    txt = (
        txt[:insert_at]
        + '\n# Make internal helpers importable by other modules\n__all__ = ["run_plugin", "_call_plugin_entrypoint", "PLUGIN_REGISTRY", "ALIASES"]\n\n'
        + txt[insert_at:]
    )

# 3) Targeted un-escaping of \" in dict literals we intentionally introduced.
txt = re.sub(
    r'\{\\"task\\":\s*\\"triage_agent\\",\s*\\"scan_file\\":\s*scan_path\}',
    '{"task": "triage_agent", "scan_file": scan_path}',
    txt,
)
txt = re.sub(
    r'\{\\"task\\":\s*\\"exploit_predictor\\",\s*\\"output_path\\":\s*output_path\}',
    '{"task": "exploit_predictor", "output_path": output_path}',
    txt,
)

# 4) Fix broken multi-line prints around the "Running plugin" line (merge artifact).
# Convert:
#   print(f"\n[✔] Running plugin: {plugin_key}...\n")
txt = re.sub(
    r'print\(\s*f"\s*\n\s*\[✔\]\s*Running plugin:\s*\{plugin_key\}\.\.\.\s*\n"\s*\)',
    'print(f"\\n[✔] Running plugin: {plugin_key}...\\n")',
    txt,
)

# 5) Fix the OWASP ZAP cancel print if it contains escaped quotes.
txt = txt.replace(
    'print(\\"\\n[❌] Scan cancelled by user.\\")',
    'print("\\n[❌] Scan cancelled by user.")',
)

# 6) Fix any other common accidentally escaped quotes in print strings
txt = re.sub(r'print\(\\"', 'print("', txt)
txt = re.sub(r"\\\"\)", '")', txt)

# 7) Replace any remaining \-escaped quotes in _analysis print
txt = re.sub(
    r'print\(\\"\\n\[🧠\] LLM Analysis\\n\\" \+ analysis_md \+ \\"\\n\\"\)',
    'print("\\n[🧠 LLM Analysis]\\n" + analysis_md + "\\n")',
    txt,
)

if txt != orig:
    target.write_text(txt, encoding="utf-8")
    print("[✓] Core/main.py updated.")
else:
    print("[i] No changes were necessary (file already clean).")
