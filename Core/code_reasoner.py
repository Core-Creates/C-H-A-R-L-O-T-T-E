# core/code_reasoner.py

from transformers import AutoTokenizer, AutoModelForMaskedLM
import torch
import os

class CodeReasoner:
    def __init__(self, local_path="./models/codebert"):
        if not os.path.exists(local_path):
            raise RuntimeError(f"Model not found at {local_path}. Run scripts/cache_model.py first.")
        
        self.tokenizer = AutoTokenizer.from_pretrained(local_path if os.path.exists(local_path) else "microsoft/codebert-base")
        self.model = AutoModelForMaskedLM.from_pretrained(local_path if os.path.exists(local_path) else "microsoft/codebert-base")

    def guess_missing_token(self, code_snippet):
        # Expects something like "mov eax, [MASK]"
        inputs = self.tokenizer(code_snippet, return_tensors="pt")
        mask_idx = (inputs.input_ids == self.tokenizer.mask_token_id).nonzero(as_tuple=True)[1]
        outputs = self.model(**inputs)
        predictions = outputs.logits[0, mask_idx].topk(5)
        tokens = [self.tokenizer.decode([idx]) for idx in predictions.indices[0]]
        return tokens

# Example
if __name__ == "__main__":
    cr = CodeReasoner()
    result = cr.guess_missing_token("mov eax, [MASK]")
    print("[CHARLOTTE thinks]:", result)
