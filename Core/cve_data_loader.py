from core.data_loader import load_json_file

CVE_DATA_PATH = "data/cve_dataset.json"

def load_cve_data(path=CVE_DATA_PATH):
    """
    Loads CVE dataset from a local JSON file using core.data_loader.load_json_file.
    Returns a dict mapping CVE IDs to their metadata.
    """
    data = load_json_file(path)
    if not data:
        print(f"[!] CVE dataset not found at {path}. Returning empty map.")
        return {}
    # If the dataset is a list, convert to dict by CVE ID
    if isinstance(data, list):
        return {entry.get("id"): entry for entry in data if "id" in entry}
    return data