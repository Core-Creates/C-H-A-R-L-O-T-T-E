# core/cve_data_loader.py

from datasets import load_dataset

def load_cve_data():
    """
    Loads the Cybersecurity LLM CVE dataset and returns a dictionary mapping CVE IDs to entries.
    """
    try:
        dataset = load_dataset("Bouquets/Cybersecurity-LLM-CVE")["train"]
        return {entry["cve_id"]: entry for entry in dataset}
    except Exception as e:
        print(f"[!] Failed to load CVE dataset: {e}")
        return {}
