# core/code_reasoner.py

from transformers import AutoTokenizer, AutoModelForMaskedLM
import torch

class CodeReasoner:
    def __init__(self, model_path="microsoft/codebert-base"):
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForMaskedLM.from_pretrained(model_path)

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