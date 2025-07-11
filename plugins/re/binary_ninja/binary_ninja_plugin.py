
"""
binary_ninja_plugin.py - CHARLOTTE plugin for Binary Ninja automation.
Loads a binary, prints function names, and can be extended for further analysis.
"""

import os
try:
    import binaryninja as bn
except ImportError:
    bn = None

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

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python binary_ninja_plugin.py <binary_file>")
    else:
        run(sys.argv[1])
