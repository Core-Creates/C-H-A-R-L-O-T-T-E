# plugins/intell/phishing_guard/api.py
from fastapi import FastAPI
from pydantic import BaseModel
from .score import score_url

app = FastAPI(title="CHARLOTTE Phishing Guard")

class ScanIn(BaseModel):
    url: str
    html: str | None = None

class ScanOut(BaseModel):
    risk: int
    recommendation: str
    ml_prob: float
    rule_score: int
    reasons: list[str]

@app.post("/scan", response_model=ScanOut)
def scan(inp: ScanIn):
    res = score_url(inp.url, inp.html)
    return ScanOut(**{k:res[k] for k in ["risk","recommendation","ml_prob","rule_score","reasons"]})
