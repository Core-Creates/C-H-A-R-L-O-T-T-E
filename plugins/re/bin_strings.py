"""
bin_strings.py

Plugin for extracting printable strings from a binary file,
optionally scoring them by entropy to identify encoded or suspicious content.
"""

import os
import string
import math
from core.logger import log_plugin_event


# ---------------------------------------------------------------
# Check if a given string is composed only of printable ASCII
# ---------------------------------------------------------------
def is_printable_ascii(s):
    """Returns True if all characters in s are printable ASCII."""
    return all(c in string.printable for c in s)


# ---------------------------------------------------------------
# Calculate Shannon entropy of a string (higher = more random)
# ---------------------------------------------------------------
def calculate_entropy(data):
    """Shannon entropy calculation."""
    if not data:
        return 0.0
    freq = {c: data.count(c) for c in set(data)}
    entropy = -sum((f / len(data)) * math.log2(f / len(data)) for f in freq.values())
    return round(entropy, 3)


# ---------------------------------------------------------------
# Core string extraction logic
# Scans the binary for printable ASCII strings of length >= min_len
# Returns a list of (string, offset, entropy) tuples
# ---------------------------------------------------------------
def extract_strings(file_path, min_len=4):
    """
    Reads the binary file and extracts printable ASCII strings.

    Args:
        file_path: Path to the binary file.
        min_len: Minimum length of printable strings to consider.

    Returns:
        List of (string, offset, entropy) tuples.
    """
    results = []
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        current = b""
        base_offset = 0

        # Loop through each byte in the binary
        for i, byte in enumerate(data):
            if 32 <= byte <= 126:  # Check for printable ASCII range
                if not current:
                    base_offset = i  # Start of a new string
                current += bytes([byte])
            else:
                # Save current string if it's long enough
                if len(current) >= min_len:
                    decoded = current.decode("ascii", errors="ignore")
                    entropy = calculate_entropy(decoded)
                    results.append((decoded, base_offset, entropy))
                current = b""

        # Catch trailing string at EOF
        if len(current) >= min_len:
            decoded = current.decode("ascii", errors="ignore")
            entropy = calculate_entropy(decoded)
            results.append((decoded, base_offset, entropy))

        return results

    except Exception as e:
        log_plugin_event("bin_strings", f"[ERROR] Failed to extract strings: {str(e)}")
        return []


# ---------------------------------------------------------------
# Plugin entry point
# Invoked by plugin_manager with parsed CLI args
# ---------------------------------------------------------------
def run(args):
    file_path = args.get("file")

    # Validate input
    if not file_path or not os.path.exists(file_path):
        return "[ERROR] Valid binary file path not provided."

    # Log plugin start
    log_plugin_event("bin_strings", f"Extracting strings from {file_path}")

    # Run extraction
    strings_with_entropy = extract_strings(file_path)

    if not strings_with_entropy:
        return "[INFO] No printable strings found."

    # Format output for display
    output_lines = []
    for s, offset, entropy in strings_with_entropy:
        output_lines.append(f"@0x{offset:08X} | Entropy: {entropy:.3f} | {s}")

    return "\n".join(output_lines)
