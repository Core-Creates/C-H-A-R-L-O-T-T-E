# utils/io.py
import json
from datetime import datetime
from pathlib import Path


def save_json(obj, *parts) -> str:
    path = Path(*parts)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
    return str(path.resolve())


def timestamp() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
