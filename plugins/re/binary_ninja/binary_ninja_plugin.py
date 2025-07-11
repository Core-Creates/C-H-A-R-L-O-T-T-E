"""
binary_ninja_plugin.py - CHARLOTTE plugin for Binary Ninja automation.
Loads a binary, prints function names, and can be extended for further analysis.
"""

import os
import sys
import platform

bn = None  # Fallback reference to prevent NameErrors if import fails

# ────────────────────────────────────────────────────────────────────────────────
# CHARLOTTE Plugin: Binary Ninja Compatibility Layer
# Auto-detects missing API path, patches sys.path, and handles license gracefully
# ────────────────────────────────────────────────────────────────────────────────

def try_patch_binaryninja_path():
    bn_default_path = r"C:\Program Files\Vector35\BinaryNinja\python"
    if platform.system() == "Windows":
        if os.path.isdir(bn_default_path) and bn_default_path not in sys.path:
            print(f"[!] Binary Ninja API not found in sys.path — attempting to patch...")
            sys.path.insert(0, bn_default_path)
            print(f"[+] Added Binary Ninja API path: {bn_default_path}")
        else:
            print("[*] Binary Ninja API path already present or not found.")
    else:
        print("[!] CHARLOTTE Binary Ninja auto-patching is only implemented for Windows.")

try_patch_binaryninja_path()

# ────────────────────────────────────────────────────────────────────────────────
# Try importing Binary Ninja API
# ────────────────────────────────────────────────────────────────────────────────

try:
    import binaryninja as bn
    from binaryninja import BinaryViewType, license

    if not license.is_valid():
        print(
            "\n[!] Binary Ninja license is invalid or missing."
            "\n    → Please launch Binary Ninja GUI once and activate your license."
            "\n    → CHARLOTTE will continue, but core analysis may fail.\n"
        )

except ImportError:
    print(
        "\n[!] Binary Ninja API is not installed or not found in this environment.\n"
        "    → Make sure to run install_api.py from your Binary Ninja install directory:\n"
        f"       python \"C:/Program Files/Vector35/BinaryNinja/scripts/install_api.py\" --install {sys.prefix}\n"
        "    → CHARLOTTE will continue, but Binary Ninja features will be skipped.\n"
    )
    bn = None

# ────────────────────────────────────────────────────────────────────────────────
# Headless analysis entry point
# ────────────────────────────────────────────────────────────────────────────────

def run(target_path):
    """Run Binary Ninja headless analysis on the given binary and print function names."""
    if bn is None:
        print("[!] Binary Ninja Python API is not installed. Please install Binary Ninja and its Python bindings.")
        return
    if not os.path.isfile(target_path):
        print(f"[!] File not found: {target_path}")
        return
    bv = bn.BinaryViewType.get_view_of_file(target_path)
    bv.update_analysis_and_wait()
    print(f"[CHARLOTTE] Functions in {target_path}:")
    for func in bv.functions:
        print(f" - {func.name}")

# ────────────────────────────────────────────────────────────────────────────────
# CLI usage
# ────────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python binary_ninja_plugin.py <binary_file>")
    else:
        run(sys.argv[1])
        print(f"[CHARLOTTE] Running Binary Ninja analysis on: {sys.argv[1]}")
        sys.exit(0)