"""
ghidra.py - CHARLOTTE plugin to run Ghidra headless analyzer on a binary.

Supports automation of scripts, batch disassembly, and data extraction.
Cross-platform support for Windows and Linux.
"""

import os
import subprocess
import platform
from datetime import datetime

# CHARLOTTE plugin metadata
PLUGIN_META = {
    "name": "Ghidra Headless Runner",
    "version": "1.1",
    "author": "CHARLOTTE",
    "category": "reverse_engineering",
    "description": "Runs Ghidra's headless analyzer on a target binary using a specified script. Supports Windows and Linux."
}

# Get OS type
IS_WINDOWS = platform.system() == "Windows"

# Determine Ghidra install directory and analyzer path
GHIDRA_INSTALL_DIR = os.environ.get(
    "GHIDRA_PATH",
    r"C:\ghidra_10.4_PUBLIC" if IS_WINDOWS else "/opt/ghidra_10.4_PUBLIC"
)

HEADLESS_ANALYZER = os.path.join(
    GHIDRA_INSTALL_DIR,
    "support",
    "analyzeHeadless.bat" if IS_WINDOWS else "analyzeHeadless"
)

def run(target_path, script_path=None, project_name="charlotte_project"):
    """Runs Ghidra headless on a target binary, optionally with a custom script."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    project_dir = os.path.join("ghidra_projects", f"{project_name}_{timestamp}")
    os.makedirs(project_dir, exist_ok=True)

    cmd = [
        f'"{HEADLESS_ANALYZER}"' if IS_WINDOWS else HEADLESS_ANALYZER,
        f'"{os.path.abspath(project_dir)}"' if IS_WINDOWS else os.path.abspath(project_dir),
        project_name,
        "-import", f'"{os.path.abspath(target_path)}"' if IS_WINDOWS else os.path.abspath(target_path),
        "-deleteProject"
    ]

    if script_path:
        cmd += ["-postScript", f'"{os.path.abspath(script_path)}"' if IS_WINDOWS else os.path.abspath(script_path)]

    cmd += ["-analysisTimeoutPerFile", "120"]

    print(f"[CHARLOTTE] Running Ghidra headless analysis on {target_path}...")

    try:
        result = subprocess.run(
            " ".join(cmd) if IS_WINDOWS else cmd,
            capture_output=True,
            text=True,
            check=True,
            shell=IS_WINDOWS
        )
        print(result.stdout)
        return {"status": "success", "output": result.stdout}
    except subprocess.CalledProcessError as e:
        print("[!] Ghidra failed:", e.stderr)
        return {"status": "error", "error": e.stderr}

