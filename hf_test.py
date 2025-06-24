from datasets import load_dataset
ds1 = load_dataset("AlicanKiraz0/All-CVE-Records-Training-Dataset")["train"]
ds2 = load_dataset("Bouquets/Cybersecurity-LLM-CVE")["train"]

print(ds1.features)  # Will show available columns
print(ds2.features)

print(f"Dataset 1 has {len(ds1)} records.")