# scripts/tamper_sbom.py
import json
import random
from pathlib import Path

SBOM_DIR = Path("sboms")
OUT_DIR = Path("sboms_tampered")
OUT_DIR.mkdir(exist_ok=True)


def flip_hash(h):
    # simple mutation: change some characters
    return "".join(
        (c if random.random() > 0.2 else ("0" if c != "0" else "1")) for c in h
    )


for p in SBOM_DIR.glob("*.json"):
    data = json.loads(p.read_text(encoding="utf-8"))
    # export two variants: one 'clean' copy and one 'tampered' copy that will be labeled negative
    clean_out = OUT_DIR / f"{p.stem}.clean.json"
    tampered_out = OUT_DIR / f"{p.stem}.tampered.json"
    clean_out.write_text(json.dumps(data, indent=2), encoding="utf-8")

    # Basic tamper operations:
    # 1) if there are components with "hashes" or "checksum", flip a few
    if isinstance(data.get("components"), list):
        for comp in data["components"]:
            if isinstance(comp.get("hashes"), list) and comp["hashes"]:
                for h in comp["hashes"]:
                    if isinstance(h, dict) and "value" in h:
                        if random.random() < 0.3:
                            h["value"] = flip_hash(h["value"])
            # 2) randomly remove package version
            if random.random() < 0.1:
                comp.pop("version", None)

    # 3) remove or corrupt top-level provenance
    if random.random() < 0.2:
        data.pop("metadata", None)

    # write tampered version
    tampered_out.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print("wrote", clean_out, tampered_out)
