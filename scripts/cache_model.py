# scripts/cache_model.py

# This script downloads the CodeBERT model and tokenizer, then saves them locally.
# You can run this script to cache the model for later use.
from transformers import AutoTokenizer, AutoModelForMaskedLM

model_name = "microsoft/codebert-base"
save_path = "./models/codebert"

# Download and save tokenizer + model
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForMaskedLM.from_pretrained(model_name)

tokenizer.save_pretrained(save_path)
model.save_pretrained(save_path)

print(f"Model cached locally at {save_path}")
