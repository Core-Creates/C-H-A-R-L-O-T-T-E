"""
bin_strings.py

Plugin for extracting printable strings from a binary file,
optionally scoring them by entropy to identify encoded or suspicious content.
Supports filtering and sorting based on entropy.
"""

import os
import string
import math
from core.logger import log_plugin_event


# ---------------------------------------------------------------
# Check if a given string is composed only of printable ASCII
# ---------------------------------------------------------------
def is_printable_ascii(s):
    return all(c in string.printable for c in s)


# ---------------------------------------------------------------
# Calculate Shannon entropy of a string (higher = more random)
# ---------------------------------------------------------------
def calculate_entropy(data):
    if not data:
        return 0.0
    freq = {c: data.count(c) for c in set(data)}
    entropy = -sum((f / len(data)) * math.log2(f / len(data)) for f in freq.values())
    return round(entropy, 3)


# ---------------------------------------------------------------
# Extract printable ASCII strings from a binary file
# ---------------------------------------------------------------
def extract_strings(file_path, min_len=4):
    results = []
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        current = b""
        base_offset = 0

        for i, byte in enumerate(data):
            if 32 <= byte <= 126:
                if not current:
                    base_offset = i
                current += bytes([byte])
            else:
                if len(current) >= min_len:
                    decoded = current.decode("ascii", errors="ignore")
                    entropy = calculate_entropy(decoded)
                    results.append((decoded, base_offset, entropy))
                current = b""

        # Handle trailing string
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
# ---------------------------------------------------------------
def run(args):
    file_path = args.get("file")
    threshold = float(args.get("entropy_threshold", 0))  # Optional: filter below this
    sort_by_entropy = args.get("sort_by_entropy", "false").lower() == "true"

    if not file_path or not os.path.exists(file_path):
        return "[ERROR] Valid binary file path not provided."

    log_plugin_event("bin_strings", f"Extracting strings from {file_path} (threshold={threshold}, sort={sort_by_entropy})")

    # Extract all printable strings with entropy scores
    strings_with_entropy = extract_strings(file_path)

    # Filter out strings below entropy threshold
    filtered = [t for t in strings_with_entropy if t[2] >= threshold]

    if not filtered:
        return f"[INFO] No strings found above entropy threshold {threshold}."

    # Optional: sort by descending entropy
    if sort_by_entropy:
        filtered = sorted(filtered, key=lambda x: x[2], reverse=True)

    # Format output
    output_lines = []
    for s, offset, entropy in filtered:
        output_lines.append(f"@0x{offset:08X} | Entropy: {entropy:.3f} | {s}")

    return "\n".join(output_lines)
