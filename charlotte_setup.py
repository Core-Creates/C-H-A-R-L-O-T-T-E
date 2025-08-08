# charlotte_setup.py

# scripts/cache_model.py
# This script downloads the CodeBERT model and tokenizer, then saves them locally.
# You can run this script to cache the model for later use.

# This script downloads the CodeBERT model and tokenizer, then saves them locally.
# You can run this script to cache the model for later use.

import os
import json
from matplotlib.pylab import f
from transformers import AutoTokenizer, AutoModelForMaskedLM

def cache_model(model_name, save_path):
    if not os.path.exists(save_path):
        print(f"Downloading and caching {model_name}...")
        tokenizer = AutoTokenizer.from_pretrained(model_name)
        model = AutoModelForMaskedLM.from_pretrained(model_name)
        tokenizer.save_pretrained(save_path)
        model.save_pretrained(save_path)
        print("Model cached.")
    else:
        print(f"Model already cached at {save_path}")

if __name__ == "__main__":
    #cache_model("microsoft/codebert-base", "./models/codebert")
# This script is intended to be run as a standalone module to configure CHARLOTTE's user settings.
    data = json.load(f)
    if isinstance(data, list):
        for i, record in enumerate(data):
            try:
                features = [
                    float(record["cvss_base"]),
                    float(record["cvss_impact"]),
                    float(record["exploitability_score"]),
                    int(record["is_remote"]),
                    int(record["cwe_id"])
                ]
                data.append(features)
            except (KeyError, ValueError) as e:
                print(f"[!] Skipping malformed JSON record #{i + 1}: {e}")
    else:
        print("[!] JSON file must contain an array of records.")
        sys.exit(1)
