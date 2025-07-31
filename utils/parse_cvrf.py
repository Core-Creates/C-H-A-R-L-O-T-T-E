# ******************************************************************************************
# utils/parse_cvrf.py
# Parses a CVRF XML file and exports extracted features and labels as CSV files
# ******************************************************************************************

import xml.etree.ElementTree as ET
import os
import csv
import argparse

# ==========================================================================================
# CVRF Parser
# ==========================================================================================

def parse_cvrf_xml(xml_path):
    """
    Parses a CVRF XML file and returns feature matrix X and label vector y.

    Features:
        - CVSS BaseScore (float)
        - ImpactScore (float)
        - ExploitabilityScore (float)
        - Is Remote (1 if AttackVector == "NETWORK", else 0)
        - CWE ID (numeric code)
    Labels:
        - Severity class (0: Low, 1: Medium, 2: High, 3: Critical)
    """
    ns = {
        'vuln': 'http://www.icasi.org/CVRF/schema/vuln/1.1',
        'cvss': 'http://www.first.org/cvss/v3.0',
        'cwe': 'http://www.mitre.org/cwe'
    }

    tree = ET.parse(xml_path)
    root = tree.getroot()

    X = []
    y = []

    for vuln in root.findall(".//vuln:Vulnerability", ns):
        try:
            # Extract numerical features
            cvss_base = float(vuln.findtext(".//cvss:BaseScore", default="0.0", namespaces=ns))
            impact = float(vuln.findtext(".//cvss:ImpactScore", default="0.0", namespaces=ns))
            exploitability = float(vuln.findtext(".//cvss:ExploitabilityScore", default="0.0", namespaces=ns))

            # Remote exploit indicator
            attack_vector = vuln.findtext(".//cvss:AttackVector", default="LOCAL", namespaces=ns).upper()
            is_remote = 1 if attack_vector == "NETWORK" else 0

            # CWE ID parsing
            cwe_raw = vuln.findtext(".//cwe:CWE", default="0", namespaces=ns)
            try:
                cwe_id = int(cwe_raw.split("-")[1]) if "-" in cwe_raw else int(cwe_raw)
            except:
                cwe_id = 0

            # Severity classification
            severity = vuln.findtext(".//cvss:BaseSeverity", default="LOW", namespaces=ns).upper()
            severity_map = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
            y_class = severity_map.get(severity, 0)

            # Append sample
            X.append([cvss_base, impact, exploitability, is_remote, cwe_id])
            y.append([y_class])

        except Exception as e:
            print(f"[!] Skipping malformed entry: {e}")

    return X, y

# ==========================================================================================
# CSV Writer
# ==========================================================================================

def write_csv(data, path, header=None):
    with open(path, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        if header:
            writer.writerow(header)
        writer.writerows(data)

# ==========================================================================================
# Main Execution
# ==========================================================================================

def main():
    parser = argparse.ArgumentParser(description="Parse CVRF XML and export features/labels CSVs.")
    parser.add_argument("--xml_file", help="Path to CVRF XML file (e.g. allitems-cvrf.xml)")
    parser.add_argument("--outdir", default="data/parsed", help="Directory to save features.csv and labels.csv")
    args = parser.parse_args()

    # Prompt user for XML file path if not provided
    if not args.xml_file:
        user_input = input("[?] Enter path to CVRF XML file (default = data/allitems-cvrf.xml): ").strip()
        args.xml_file = user_input if user_input else "data/allitems-cvrf.xml"

    # Verify the file exists
    if not os.path.exists(args.xml_file):
        print(f"[!] File not found: {args.xml_file}")
        return

    # Optional custom output dir
    print(f"[*] Output directory (default = {args.outdir})")
    custom_outdir = input("    Press Enter to accept or type a new path: ").strip()
    if custom_outdir:
        args.outdir = custom_outdir

    os.makedirs(args.outdir, exist_ok=True)

    # Begin parsing
    print(f"[*] Parsing {args.xml_file} ...")
    X, y = parse_cvrf_xml(args.xml_file)

    features_path = os.path.join(args.outdir, "features.csv")
    labels_path = os.path.join(args.outdir, "labels.csv")

    # Write to CSV
    write_csv(X, features_path, header=["cvss_base", "impact", "exploitability", "is_remote", "cwe_id"])
    write_csv(y, labels_path, header=["severity_class"])

    print(f"[+] Features saved to {features_path}")
    print(f"[+] Labels saved to {labels_path}")
    print(f"[✓] Parsed {len(X)} entries successfully.")

if __name__ == "__main__":
    main()
