# utils/priority.py
def classify(score: int, t: dict) -> str:
    if score >= t["high"]:
        return "High"
    if score >= t["medium"]:
        return "Medium"
    return "Low"
