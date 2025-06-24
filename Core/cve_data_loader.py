# core/cve_data_loader.py
#
# 🔍 CHARLOTTE CVE Data Loader
# Supports Hugging Face datasets AND MITRE's official CVRF feed
#

import os
import json
import requests
import xml.etree.ElementTree as ET
from datasets import load_dataset

# ==========================================================
# Hugging Face loader
# ==========================================================
def load_hf_cve_data():
    """Loads CVE data from Hugging Face and returns a dict keyed by 'cve_id'."""
    merged_data = {}

    try:
        print("[+] Loading: AlicanKiraz0/All-CVE-Records-Training-Dataset")
        data_set1 = load_dataset("AlicanKiraz0/All-CVE-Records-Training-Dataset")["train"]
        merged_data.update({entry["cve_id"]: entry for entry in data_set1 if "cve_id" in entry})
    except Exception as e:
        print(f"[!] Failed to load AlicanKiraz0 dataset: {e}")

    try:
        print("[+] Loading: Bouquets/Cybersecurity-LLM-CVE")
        data_set2 = load_dataset("Bouquets/Cybersecurity-LLM-CVE")["train"]
        merged_data.update({entry["cve_id"]: entry for entry in data_set2 if "cve_id" in entry})
    except Exception as e:
        print(f"[!] Failed to load Bouquets dataset: {e}")

    print(f"[+] Loaded {len(merged_data)} unique CVE entries from Hugging Face.")
    return merged_data


# ==========================================================
# MITRE loader
# ==========================================================

CVRF_URL = "https://cve.mitre.org/data/downloads/allitems-cvrf.xml"

def fetch_allitems_cvrf(output_file="data/allitems-cvrf.xml"):
    """Downloads MITRE's allitems-cvrf.xml feed if not present."""
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    if not os.path.exists(output_file):  # Save a local copy
        print("[*] Downloading MITRE allitems-cvrf.xml...")
        resp = requests.get(CVRF_URL, stream=True)
        resp.raise_for_status()
        with open(output_file, "wb") as f:
            for chunk in resp.iter_content(chunk_size=1024):
                f.write(chunk)
    return output_file

def load_mitre_cve_data(output_file="data/allitems-cvrf.xml"):
    """Parses MITRE's allitems-cvrf.xml feed and returns a dict keyed by CVE ID."""
    xml_file = fetch_allitems_cvrf(output_file)

    # Parse the XML
    tree = ET.parse(xml_file)
    root = tree.getroot()

    # ✅ Extract namespace from root tag
    namespace_uri = root.tag.split("}")[0].strip("{")
    namespace = {"cvrf": namespace_uri}
    results = {}

    # Find all Vulnerability entries regardless of version
    for vuln in root.findall(".//cvrf:Vulnerability", namespace):
        cve_node = vuln.find("cvrf:CVE", namespace)
        title_node = vuln.find("cvrf:Title", namespace)

        if cve_node is None:
            continue  # Skip entries with no CVE ID
        cve_id = cve_node.text
        title = title_node.text if title_node is not None else "No title available"

        # Collect notes
        notes = []
        for note in vuln.findall("cvrf:Notes/cvrf:Note", namespace):
            if note.text:
                notes.append(note.text.strip())

        results[cve_id] = {
            "cve_id": cve_id,
            "title": title,
            "notes": notes,
            "source": "mitre_cvrf",
        }

    print(f"[+] Loaded {len(results)} CVE entries from MITRE feed.")
    return results


# ==========================================================
# Main Loader
# ==========================================================
def load_cve_data(source="hf"):
    """
    Main entry point for CHARLOTTE.
    source='hf'   -> Hugging Face
    source='mitre' -> MITRE (allitems-cvrf.xml)

    Returns:
        Dict keyed by 'cve_id'
    """
    if source == "hf":
        return load_hf_cve_data()
    elif source == "mitre":
        return load_mitre_cve_data()
    else:
        raise ValueError(f"Invalid source: {source}. Must be 'hf' or 'mitre'.")

# ==========================================================
# Save routine
# ==========================================================
def save_to_file(data, filename="data/cve_combined.json"):
    """Saves merged data to JSON."""
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Saved CVE data to {filename}")

# ==========================================================
# Main Execution
# ==========================================================
if __name__ == "__main__":
    # Hugging Face
    hf_data = load_cve_data(source="hf")
    save_to_file(hf_data, "data/cve_huggingface.json")

    # MITRE
    mitre_data = load_cve_data(source="mitre")
    save_to_file(mitre_data, "data/cve_mitre.json")
