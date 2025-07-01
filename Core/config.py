
"""
config.py

Global configuration and personality settings for C.H.A.R.L.O.T.T.E.
Supports environment-based overrides and user-level persistence.
This module defines CHARLOTTE's core settings, including LLM provider,
binary analysis options, web scanning defaults, and personality persistence.
"""

import os
import json
from dotenv import load_dotenv

# *****************************************************************************************
# 💾 Environment Variable Support
# *****************************************************************************************

# Loads variables from a `.env` file in the root if it exists.
# This lets users define secrets and paths without modifying source code.
load_dotenv()

# *****************************************************************************************
# 🧠 Core CHARLOTTE Global Configuration Dictionary
# These values control how CHARLOTTE behaves at runtime across plugin categories.
# *****************************************************************************************

CHARLOTTE_CONFIG = {
    # *** LLM Settings ***
    "LLM_PROVIDER": os.getenv("LLM_PROVIDER", "openai"),  # Options: "openai", "huggingface", "local"
    "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY", ""),  # Used when provider = openai
    "OPENAI_MODEL": os.getenv("OPENAI_MODEL", "gpt-4"),
    "HUGGINGFACE_API_KEY": os.getenv("HUGGINGFACE_API_KEY", ""),  # Used when provider = huggingface
    "HUGGINGFACE_MODEL": os.getenv("HUGGINGFACE_MODEL", "mistralai/Mistral-7B-Instruct-v0.1"),
    "LOCAL_MODEL_PATH": os.getenv("LOCAL_MODEL_PATH", ""),  # Optional Transformers local path

    # *** Binary Analysis ***
    "USE_GHIDRA": os.getenv("USE_GHIDRA", "true").lower() == "true",  # Ghidra or Binary Ninja support
    "GHIDRA_HEADLESS_PATH": os.getenv("GHIDRA_HEADLESS_PATH", "/opt/ghidra/support/analyzeHeadless"),

    # *** Web Scanning ***
    "DEFAULT_SCAN_ENGINE": os.getenv("DEFAULT_SCAN_ENGINE", "zap"),  # "zap", "burp", "custom"

    # *** Plugin Category Controls ***
    "ENABLE_REVERSE_ENGINEERING": os.getenv("ENABLE_REVERSE_ENGINEERING", "true").lower() == "true",
    "ENABLE_WEB_SCANNING": os.getenv("ENABLE_WEB_SCANNING", "true").lower() == "true",

    # *** Output & Logging Settings ***
    "VERBOSE": os.getenv("CHARLOTTE_VERBOSE", "true").lower() == "true",
    "SAVE_RESULTS": os.getenv("CHARLOTTE_SAVE_RESULTS", "true").lower() == "true",
    "RESULTS_DIR": os.getenv("CHARLOTTE_RESULTS_DIR", "data/findings/"),
}

# *****************************************************************************************
# 🎭 Personality Configuration Persistence
# Stores personality mode or slider config in user’s home directory (~/.charlotte/)
# *****************************************************************************************

# Define the user-specific CHARLOTTE config path
CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".charlotte")
CONFIG_PATH = os.path.join(CONFIG_DIR, "personality_config.json")

def load_personality_config(path=CONFIG_PATH):
    """
    Load CHARLOTTE's personality settings from user's home directory.
    Returns a dict containing either custom slider levels or a named mode.
    """
    if not os.path.exists(CONFIG_PATH):
        return {}
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def save_personality_config(config, path=CONFIG_PATH):
    """
    Save CHARLOTTE's personality mode or levels to ~/.charlotte/personality_config.json.
    Ensures the parent directory exists.
    """
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4)
# Ensure the config directory exists
os.makedirs(CONFIG_DIR, exist_ok=True)