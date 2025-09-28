# Quick evaluator that loads the saved artifacts and reports accuracy on a provided CSV

from pathlib import Path
import importlib.util
import pandas as pd
import numpy as np
import joblib
import torch
import sys

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))


def _load_module(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    return mod


merged_pred_path = HERE / "cve_severity_predictor_merged.py"
if merged_pred_path.exists():
    cve_mod = _load_module(merged_pred_path, "cve_severity_predictor_merged")
else:
    from models.cve_severity_predictor import CVESeverityNet, DEVICE  # type: ignore

SCALER_PATH = HERE / "data" / "model_weights" / "scaler_severity.pkl"
MODEL_PATH = HERE / "data" / "model_weights" / "severity_net.pt"
TEMP_PATH = HERE / "data" / "model_weights" / "temperature.npy"


def main():
    scaler = joblib.load(SCALER_PATH)
    T = float(np.load(TEMP_PATH)[0]) if TEMP_PATH.exists() else 1.0

    # Build model and load weights
    try:
        model = cve_mod.CVESeverityNet(input_dim=5)
        device = cve_mod.DEVICE
    except Exception:
        model = CVESeverityNet(input_dim=5)  # type: ignore
        device = DEVICE  # type: ignore

    model.load_state_dict(torch.load(MODEL_PATH, map_location=device))
    model.eval()

    # Evaluate on features.csv + labels.csv
    X = pd.read_csv(HERE / "features.csv").values
    y = pd.read_csv(HERE / "labels.csv").iloc[:, 0].values
    # Coerce labels
    mapping = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    y2 = []
    for v in y:
        try:
            iv = int(float(v))
            y2.append(iv if iv in (0, 1, 2, 3) else 1)
        except Exception:
            y2.append(mapping.get(str(v).strip().lower(), 1))
    y = np.array(y2, dtype=int)

    Xs = scaler.transform(X)
    with torch.no_grad():
        logits = model(torch.tensor(Xs, dtype=torch.float32).to(device))
        logits = logits / T
        preds = torch.argmax(logits, dim=1).cpu().numpy()

    from sklearn.metrics import classification_report

    rep = classification_report(
        y, preds, target_names=["Low", "Medium", "High", "Critical"]
    )
    print(rep)


if __name__ == "__main__":
    main()
