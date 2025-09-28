#!/usr/bin/env bash
set -euo pipefail
mkdir -p sboms

# Example inputs: images or local repo paths; replace with your list file
INPUTS_FILE="inputs.txt"  # one image or path per line

while read -r target || [ -n "$target" ]; do
  if [ -z "$target" ]; then
    continue
  fi
  # sanitize name
  name=$(echo "$target" | sed 's/[^a-zA-Z0-9._-]/_/g')
  out="sboms/${name}.cyclonedx.json"

  # Use Syft to produce CycloneDX JSON (syft supports cyclonedx-json output)
  syft "$target" -o cyclonedx-json > "$out" || {
    echo "[!] syft failed for $target" >&2
    continue
  }
  echo "[+] wrote $out"
done < "$INPUTS_FILE"
echo "[+] SBOM generation complete."
