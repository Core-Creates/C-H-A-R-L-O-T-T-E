# core/cve_data_loader.py

from datasets import load_dataset

def load_cve_data():
    """
    Loads CVE datasets from Hugging Face and returns a dictionary mapping CVE IDs to entries.
    Tries multiple datasets and merges them into a single dictionary.
    """
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

    print(f"[+] Loaded {len(merged_data)} unique CVE entries.")
    return merged_data
# This function loads CVE data from multiple datasets and merges them into a single dictionary.
# Each entry is keyed by its CVE ID for easy lookup.