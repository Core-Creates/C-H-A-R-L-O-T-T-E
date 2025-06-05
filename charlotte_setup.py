# charlotte_setup.py

# scripts/cache_model.py
# This script downloads the CodeBERT model and tokenizer, then saves them locally.
# You can run this script to cache the model for later use.

# This script downloads the CodeBERT model and tokenizer, then saves them locally.
# You can run this script to cache the model for later use.
import os
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
    cache_model("microsoft/codebert-base", "./models/codebert")
