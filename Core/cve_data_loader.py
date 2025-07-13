from core.data_loader import parse_xml_file

CVE_DATA_PATH = "data/all_cve_data.xml"

def load_cve_data(path=CVE_DATA_PATH):
    """
    Loads CVE dataset from a local xml file using core.data_loader.parse_xml_file.
    Returns a dict mapping CVE IDs to their metadata.
    """
    data = parse_xml_file(path)
    if not data:
        print(f"[!] CVE dataset not found at {path}. Returning empty map.")
        return {}
    # If the dataset is a list, convert to dict by CVE ID
    if isinstance(data, list):
        return {entry.get("id"): entry for entry in data if "id" in entry}
    return data