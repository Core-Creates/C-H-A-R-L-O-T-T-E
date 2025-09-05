# ******************************************************************************************
# utils/parse_json.py
# Parses a JSON log file and extracts features and semantic stage labels
# Then formats the dataset for CHARLOTTE ML training (multi-class format)
# ******************************************************************************************

# ========================
# BEGINNING OF IMPORTS
# ========================

import os
import csv
import json
import argparse
from collections import Counter

# ========================
# END OF IMPORTS
# ========================


# ==========================================================================================
# FUNCTION: parse_json_file
# Parses newline-delimited JSON logs where EventData is a JSON string.
# Extracts rich features for CHARLOTTE, including network/registry fields and threat stage.
# ==========================================================================================
def parse_json_file(file_path: str) -> tuple[list[dict], list[str]]:
    """
    Parses a JSONL Sysmon log file for CHARLOTTE ML training.

    Args:
        file_path (str): Path to the Sysmon logs.

    Returns:
        tuple: (features_list, labels_list)
            features_list (List[Dict]): Parsed features including protocol, IP, severity, etc.
            labels_list (List[str]): Semantic stage labels (e.g., 'benign', 'exploit_attempt')
    """

    features_list = []
    labels_list = []

    # Valid semantic stages
    STAGE_CATEGORIES = ["benign", "exploit_attempt", "data_exfil", "persistence"]

    try:
        with open(file_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    print(f"[!] Skipping malformed JSON: {e}")
                    continue

                # Extract the inner EventData JSON from the string
                try:
                    event_data = json.loads(entry.get("EventData", "{}"))
                except json.JSONDecodeError:
                    print("[!] Skipping entry with unparsable EventData")
                    continue

                event_id = entry.get("EventID", None)

                # Shared features across all event types
                features = {
                    "timestamp": event_data.get("UtcTime"),
                    "eventID": event_id,
                    "image": event_data.get("Image"),
                    "commandLine": event_data.get("CommandLine"),
                    "parentImage": event_data.get("ParentImage"),
                    "processId": event_data.get("ProcessId"),
                    "filePath": event_data.get("TargetFilename")
                    or event_data.get("TargetObject"),
                    "protocol": event_data.get("Protocol"),
                    "destinationIp": event_data.get("DestinationIp"),
                    "user": event_data.get("User"),
                }

                # Default values
                severity = 0
                stage = "benign"

                # Stage: exploit_attempt (Log4Shell / JNDI pattern in command line)
                cmd = event_data.get("CommandLine", "") or ""
                if "jndi:" in cmd.lower():
                    severity = 3
                    stage = "exploit_attempt"

                # Stage: data_exfil (Sysmon EventID 3 + AWS metadata IP)
                if event_id == 3:
                    dst = (event_data.get("DestinationIp") or "").strip()
                    if dst.startswith("169.254.169.254"):
                        severity = 2
                        stage = "data_exfil"

                # Stage: persistence (Sysmon EventID 12 modifying proxy registry key)
                if event_id == 12:
                    reg_path = (event_data.get("TargetObject") or "").lower()
                    if "internet settings" in reg_path and "proxy" in reg_path:
                        severity = 1
                        stage = "persistence"

                # Ensure only valid stage labels are used
                if stage not in STAGE_CATEGORIES:
                    stage = "benign"

                # Add severity and stage to the feature set
                features["severity"] = severity
                features["stage"] = stage

                # Debug output
                print(
                    f"[DEBUG] EventID: {event_id}, Stage: {stage}, Severity: {severity}"
                )

                # Append results
                features_list.append(features)
                labels_list.append(stage)

    except FileNotFoundError:
        print(f"[!] File not found: {file_path}")
        return [], []

    return features_list, labels_list


# ==========================================================================================
# FUNCTION: save_to_csv
# Saves parsed features and labels to CSV files formatted for CHARLOTTE ML training
# ==========================================================================================
def save_to_csv(
    features: list[dict], labels: list[str], output_dir: str = "data/parsed"
) -> None:
    os.makedirs(output_dir, exist_ok=True)
    feature_keys = list(features[0].keys()) if features else []

    # Save features.csv
    features_path = os.path.join(output_dir, "charlotte_features.csv")
    with open(features_path, "w", newline="", encoding="utf-8") as f_csv:
        writer = csv.DictWriter(f_csv, fieldnames=feature_keys)
        writer.writeheader()
        writer.writerows(features)
    print(f"[+] Saved features to {features_path}")

    # Save labels.csv
    labels_path = os.path.join(output_dir, "charlotte_labels.csv")
    with open(labels_path, "w", newline="", encoding="utf-8") as l_csv:
        writer = csv.writer(l_csv)
        writer.writerow(["label"])
        for label in labels:
            writer.writerow([label])
    print(f"[+] Saved labels to {labels_path}")

    # Save combined dataset.csv
    dataset_path = os.path.join(output_dir, "charlotte_dataset.csv")
    with open(dataset_path, "w", newline="", encoding="utf-8") as d_csv:
        writer = csv.DictWriter(d_csv, fieldnames=feature_keys + ["label"])
        writer.writeheader()
        for feat, lbl in zip(features, labels):
            row = feat.copy()
            row["label"] = lbl
            writer.writerow(row)
    print(f"[+] Saved combined dataset to {dataset_path}")


# ==========================================================================================
# CLI ENTRY POINT
# Allows this script to be used as a standalone CLI tool
# ==========================================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Parse JSON log file for CHARLOTTE ML training."
    )
    parser.add_argument("file_path", help="Path to the JSON log file")
    args = parser.parse_args()

    # Parse the input file
    features, labels = parse_json_file(args.file_path)

    if not features:
        print("[!] No data extracted. Aborting.")
        exit(1)

    # Show sample output
    print(f"[+] Extracted {len(features)} feature sets and {len(labels)} labels.")
    print("[+] Sample feature 1:", features[0])
    if len(features) > 1:
        print("[+] Sample feature 2:", features[1])
    print("[+] Sample labels:", labels[:2])

    # Show label distribution summary
    label_counter = Counter(labels)
    print("[+] Label distribution:")
    for label, count in label_counter.items():
        print(f"    {label}: {count}")

    # Save formatted data to disk
    save_to_csv(features, labels)

# ******************************************************************************************
# END OF utils/parse_json.py
# ******************************************************************************************
