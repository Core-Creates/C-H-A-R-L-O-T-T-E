"""
config.py

Global configuration settings for C.H.A.R.L.O.T.T.E.
Supports loading from environment variables, `.env`, or hardcoded defaults.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

# Global Configuration Dictionary
CHARLOTTE_CONFIG = {
    # === LLM Settings ===
    "LLM_PROVIDER": os.getenv("LLM_PROVIDER", "openai"),  # or "huggingface", "local"
    "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY", ""),
    "OPENAI_MODEL": os.getenv("OPENAI_MODEL", "gpt-4"),

    # === Binary Analysis ===
    "USE_GHIDRA": os.getenv("USE_GHIDRA", "true").lower() == "true",
    "GHIDRA_HEADLESS_PATH": os.getenv("GHIDRA_HEADLESS_PATH", "/opt/ghidra/support/analyzeHeadless"),

    # === Web Scanning ===
    "DEFAULT_SCAN_ENGINE": os.getenv("DEFAULT_SCAN_ENGINE", "zap"),  # or "burp", "custom"

    # === Plugin Controls ===
    "ENABLE_REVERSE_ENGINEERING": os.getenv("ENABLE_REVERSE_ENGINEERING", "true").lower() == "true",
    "ENABLE_WEB_SCANNING": os.getenv("ENABLE_WEB_SCANNING", "true").lower() == "true",

    # === Output/Logging ===
    "VERBOSE": os.getenv("CHARLOTTE_VERBOSE", "true").lower() == "true",
    "SAVE_RESULTS": os.getenv("CHARLOTTE_SAVE_RESULTS", "true").lower() == "true",
    "RESULTS_DIR": os.getenv("CHARLOTTE_RESULTS_DIR", "data/findings/"),
}
