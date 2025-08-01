# ******************************************************************************************
# cli/batch_predict_severity.py
# Command-line tool for batch CVE severity prediction using CHARLOTTE's neural model
# Supports CSV and JSON input formats
# ******************************************************************************************

import os
import sys
import csv
import json
import argparse

# Add CHARLOTTE root directory to sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
    
# Now you can import from models/cve_severity_predictor.py
from models.cve_severity_predictor import predict_severity, predict_batch, load_model, load_scaler

# ==========================================================================================
# FUNCTION: load_input_data
# Reads CVE features from CSV or JSON file and formats for prediction
# ==========================================================================================
def load_input_data(file_path):
    """
    Loads a list of CVE feature vectors from a .csv or .json file.

    Returns:
        List[List[float]]: List of CVE records in expected format.
    """
    if not os.path.exists(file_path):
        print(f"[!] File not found: {file_path}")
        sys.exit(1)

    ext = os.path.splitext(file_path)[1].lower()
    data = []

    if ext == ".csv":
        with open(file_path, newline='', encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                try:
                    features = [
                        float(row["cvss_base"]),
                        float(row["cvss_impact"]),
                        float(row["exploitability_score"]),
                        int(row["is_remote"]),
                        int(row["cwe_id"])
                    ]
                    data.append(features)
                except (KeyError, ValueError) as e:
                    print(f"[!] Skipping malformed row: {row} — {e}")

    elif ext == ".json":
        with open(file_path, "r", encoding="utf-8") as jsonfile:
            try:
                raw = json.load(jsonfile)
                for entry in raw:
                    features = [
                        float(entry["cvss_base"]),
                        float(entry["cvss_impact"]),
                        float(entry["exploitability_score"]),
                        int(entry["is_remote"]),
                        int(entry["cwe_id"])
                    ]
                    data.append(features)
            except (KeyError, ValueError, json.JSONDecodeError) as e:
                print(f"[!] JSON parsing error: {e}")
                sys.exit(1)
    else:
        print(f"[!] Unsupported file format: {ext}")
        sys.exit(1)

    return data

# ==========================================================================================
# FUNCTION: save_predictions
# Optionally saves predictions to disk
# ==========================================================================================
def save_predictions(output_path, predictions):
    with open(output_path, "w", newline='', encoding="utf-8") as out_csv:
        writer = csv.writer(out_csv)
        writer.writerow(["predicted_severity"])
        for label in predictions:
            writer.writerow([label])
    print(f"[+] Saved predictions to {output_path}")

# ==========================================================================================
# MAIN ENTRY POINT
# ==========================================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bulk CVE Severity Prediction CLI Tool (CHARLOTTE)")
    parser.add_argument("input_file", help="Path to input CSV or JSON file with CVE features")
    parser.add_argument("--output", help="Optional output CSV file to save predictions", default=None)

    args = parser.parse_args()
    cve_records = load_input_data(args.input_file)

    if not cve_records:
        print("[!] No valid CVE records found. Exiting.")
        sys.exit(1)

    print(f"[+] Loaded {len(cve_records)} CVE records. Running batch prediction...")

    # Load model and scaler once
    model = load_model()
    scaler = load_scaler()

    predictions = predict_batch(cve_records, model=model, scaler=scaler)

    for i, severity in enumerate(predictions):
        print(f"    CVE #{i+1}: {severity}")

    if args.output:
        save_predictions(args.output, predictions)
