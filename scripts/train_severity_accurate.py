# /scripts/train_severity_accurate.py
# ******************************************************************************************
# Trains an improved CVESeverityNet using pre-parsed CVE data from CSVs
# This script expects (by default):
#   - data/parsed/features.csv
#   - data/parsed/labels.csv  (or data/charlotte_labels.csv, data/labels.csv)
# You can override with: --features path/to/features.csv --labels path/to/labels.csv
# These can be generated using: python utils/parse_cvrf.py data/allitems-cvrf.xml
# ******************************************************************************************

import sys
import json
import torch
import joblib
import argparse
import numpy as np
import pandas as pd
import torch.nn as nn
import importlib.util
from pathlib import Path
from torch.utils.data import TensorDataset, DataLoader
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score, classification_report, confusion_matrix


HERE = Path(__file__).parent
ROOT_DIR = HERE.parent
DATA_DIR = ROOT_DIR / "data"
PARSED_DIR = DATA_DIR / "parsed"

# Ensure project imports work when running from anywhere
sys.path.insert(0, str(ROOT_DIR))


# Load merged predictor module to ensure compatibility with CHARLOTTE
def _load_module(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader, "Failed to load module spec"
    spec.loader.exec_module(mod)  # type: ignore
    return mod


# Try merged file next to repo root (if user dropped it there); else use models/
merged_pred_path = ROOT_DIR / "cve_severity_predictor_merged.py"
if merged_pred_path.exists():
    cve_mod = _load_module(merged_pred_path, "cve_severity_predictor_merged")
else:
    # fallback: standard project layout
    from models.cve_severity_predictor import (
        CVESeverityNet as _CVESeverityNet,
        DEVICE as _DEVICE,
    )  # type: ignore

    class _Dummy:
        pass

    cve_mod = _Dummy()
    cve_mod.CVESeverityNet = _CVESeverityNet
    cve_mod.DEVICE = _DEVICE

# Outputs go under repo data/
OUT_DIR = DATA_DIR / "model_weights"
REP_DIR = DATA_DIR / "reports"
OUT_DIR.mkdir(parents=True, exist_ok=True)
REP_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH = OUT_DIR / "severity_net.pt"
SCALER_PATH = OUT_DIR / "scaler_severity.pkl"
TEMP_PATH = OUT_DIR / "temperature.npy"
METRICS_JSON = REP_DIR / "metrics.json"
CLF_CSV = REP_DIR / "classification_report.csv"
CM_PNG = REP_DIR / "confusion_matrix.png"

SEED = 1337
np.random.seed(SEED)
torch.manual_seed(SEED)


def _load_labels_frame(labels_path: Path | None) -> pd.DataFrame:
    # Priority: explicit arg → data/parsed/labels.csv → data/labels.csv → data/charlotte_labels.csv
    if labels_path and labels_path.exists():
        return pd.read_csv(labels_path)
    for p in [
        PARSED_DIR / "labels.csv",
        DATA_DIR / "labels.csv",
        DATA_DIR / "charlotte_labels.csv",
    ]:
        if p.exists():
            return pd.read_csv(p)
    raise FileNotFoundError(
        "Could not find labels.csv or charlotte_labels.csv under data/ or data/parsed/. Use --labels to specify a path."
    )


def _coerce_labels(y_raw) -> np.ndarray:
    # Accept ints 0..3, or strings like "low/medium/high/critical"
    mapping = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    out = []
    for v in y_raw:
        if pd.isna(v):
            out.append(1)  # default to "medium"
            continue
        try:
            iv = int(float(v))
            if iv in (0, 1, 2, 3):
                out.append(iv)
                continue
        except Exception:
            pass
        s = str(v).strip().lower()
        out.append(mapping.get(s, 1))
    return np.array(out, dtype=int)


def _class_weights(y: np.ndarray) -> torch.Tensor:
    # inverse-frequency weights
    classes, counts = np.unique(y, return_counts=True)
    freq = counts / counts.sum()
    w = 1.0 / np.clip(freq, 1e-6, None)
    w = w / np.mean(w)
    full = np.ones(4, dtype=float)
    for c, val in zip(classes, w):
        if 0 <= c <= 3:
            full[c] = val
    return torch.tensor(full, dtype=torch.float32)


class BetterNet(nn.Module):
    # Wider + BatchNorm + Dropout improves accuracy & calibration
    def __init__(self, input_dim=5, hidden=64, hidden2=32, dropout=0.2):
        super().__init__()
        self.bn_in = nn.BatchNorm1d(input_dim)
        self.fc1 = nn.Linear(input_dim, hidden)
        self.bn1 = nn.BatchNorm1d(hidden)
        self.fc2 = nn.Linear(hidden, hidden2)
        self.bn2 = nn.BatchNorm1d(hidden2)
        self.out = nn.Linear(hidden2, 4)
        self.do = nn.Dropout(dropout)

    def forward(self, x):
        x = self.bn_in(x)
        x = torch.relu(self.bn1(self.fc1(x)))
        x = self.do(x)
        x = torch.relu(self.bn2(self.fc2(x)))
        x = self.do(x)
        return self.out(x)


def _temperature_scale(logits: torch.Tensor, T: float) -> torch.Tensor:
    return logits / T


def _find_temperature(model, loader, device) -> float:
    # Optimize temperature on validation set with NLL
    temp = torch.tensor(1.0, requires_grad=True, device=device)
    opt = torch.optim.LBFGS([temp], lr=0.1, max_iter=50)
    nll = nn.CrossEntropyLoss()
    logits_all = []
    labels_all = []
    model.eval()
    with torch.no_grad():
        for xb, yb in loader:
            xb, yb = xb.to(device), yb.to(device)
            logits = model(xb)
            logits_all.append(logits)
            labels_all.append(yb)
    logits_val = torch.cat(logits_all)
    labels_val = torch.cat(labels_all)

    def closure():
        opt.zero_grad()
        loss = nll(_temperature_scale(logits_val, temp), labels_val)
        loss.backward()
        return loss

    opt.step(closure)
    return float(temp.detach().cpu().item())


def _metrics(y_true, y_pred):
    f1m = f1_score(y_true, y_pred, average="macro")
    f1w = f1_score(y_true, y_pred, average="weighted")
    return {"f1_macro": float(f1m), "f1_weighted": float(f1w)}


def _fit_once(
    X_tr, y_tr, X_va, y_va, class_w, device, epochs=60, batch=256, lr=3e-4, wd=1e-2
):
    scaler = StandardScaler()
    X_trs = scaler.fit_transform(X_tr)
    X_vas = scaler.transform(X_va)

    tr_ds = TensorDataset(
        torch.tensor(X_trs, dtype=torch.float32), torch.tensor(y_tr, dtype=torch.long)
    )
    va_ds = TensorDataset(
        torch.tensor(X_vas, dtype=torch.float32), torch.tensor(y_va, dtype=torch.long)
    )
    tr_dl = DataLoader(tr_ds, batch_size=batch, shuffle=True)
    va_dl = DataLoader(va_ds, batch_size=batch, shuffle=False)

    model = BetterNet(input_dim=X_tr.shape[1]).to(device)
    crit = nn.CrossEntropyLoss(weight=class_w.to(device))
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=wd)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=epochs)

    best_f1 = -1.0
    best_state = None
    patience = 10
    no_improve = 0

    for ep in range(1, epochs + 1):
        model.train()
        for xb, yb in tr_dl:
            xb, yb = xb.to(device), yb.to(device)
            opt.zero_grad()
            logits = model(xb)
            loss = crit(logits, yb)
            loss.backward()
            opt.step()
        sched.step()

        # Evaluate
        model.eval()
        preds = []
        ys = []
        with torch.no_grad():
            for xb, yb in va_dl:
                xb, yb = xb.to(device), yb.to(device)
                logits = model(xb)
                p = torch.argmax(logits, dim=1)
                preds.append(p.cpu().numpy())
                ys.append(yb.cpu().numpy())
        yhat = np.concatenate(preds)
        ytrue = np.concatenate(ys)
        f1m = f1_score(ytrue, yhat, average="macro")

        if f1m > best_f1:
            best_f1 = f1m
            best_state = {
                k: v.detach().cpu().clone() for k, v in model.state_dict().items()
            }
            no_improve = 0
        else:
            no_improve += 1
            if no_improve >= patience:
                break

    # Restore best
    model.load_state_dict(best_state)
    return model, scaler, best_f1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--features",
        type=str,
        default="",
        help="Path to features.csv (default: data/parsed/features.csv)",
    )
    ap.add_argument(
        "--labels", type=str, default="", help="Path to labels.csv/charlotte_labels.csv"
    )
    args = ap.parse_args()

    device = (
        cve_mod.DEVICE
        if hasattr(cve_mod, "DEVICE")
        else torch.device("cuda" if torch.cuda.is_available() else "cpu")
    )

    # Resolve features path (arg → data/parsed/features.csv → data/features.csv)
    X_path = Path(args.features) if args.features else PARSED_DIR / "features.csv"
    if not X_path.exists():
        alt = DATA_DIR / "features.csv"
        if alt.exists():
            X_path = alt
        else:
            raise FileNotFoundError(
                f"Missing features at {X_path} (also checked {alt}). Use --features to specify a path."
            )
    print(f"[*] Loading features from {X_path}")
    X = pd.read_csv(X_path).values

    # Load labels
    yf = _load_labels_frame(Path(args.labels) if args.labels else None)
    print(f"[*] Loading labels shape={yf.shape}")
    y = _coerce_labels(yf.iloc[:, 0].values)
    if len(y) != len(X):
        raise ValueError(f"Features/labels length mismatch: X={len(X)}, y={len(y)}")

    # Peek class balance
    uniq, cnt = np.unique(y, return_counts=True)
    print("[i] Class balance:", dict(zip(map(int, uniq), map(int, cnt))))

    # Split calibration set (held-out) for temperature scaling
    X_train_all, X_cal, y_train_all, y_cal = train_test_split(
        X, y, test_size=0.15, random_state=SEED, stratify=y
    )

    # Cross-validated training to pick best hyperparams
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    class_w = _class_weights(y_train_all)

    search = [
        {"epochs": 80, "batch": 256, "lr": 3e-4, "wd": 1e-2},
        {"epochs": 100, "batch": 256, "lr": 2e-4, "wd": 5e-3},
        {"epochs": 60, "batch": 128, "lr": 5e-4, "wd": 1e-2},
    ]

    best_cfg = None
    best_cv = -1.0

    for cfg in search:
        scores = []
        for tr_idx, va_idx in skf.split(X_train_all, y_train_all):
            X_tr, X_va = X_train_all[tr_idx], X_train_all[va_idx]
            y_tr, y_va = y_train_all[tr_idx], y_train_all[va_idx]
            model, scaler, f1m = _fit_once(
                X_tr, y_tr, X_va, y_va, class_w, device, **cfg
            )
            scores.append(f1m)
        mean_score = float(np.mean(scores))
        print(f"[cv] cfg={cfg} macro-F1={mean_score:.3f}")
        if mean_score > best_cv:
            best_cv = mean_score
            best_cfg = cfg

    print(f"[cv] Best config: {best_cfg} (macro-F1={best_cv:.3f})")

    # Retrain on full training set with best config
    model, scaler, _ = _fit_once(
        X_train_all, y_train_all, X_cal, y_cal, class_w, device, **best_cfg
    )

    # Temperature scaling on held-out calibration set
    Xc_s = scaler.transform(X_cal)
    cal_ds = TensorDataset(
        torch.tensor(Xc_s, dtype=torch.float32), torch.tensor(y_cal, dtype=torch.long)
    )
    cal_dl = DataLoader(cal_ds, batch_size=256, shuffle=False)
    T = _find_temperature(model, cal_dl, device)
    np.save(TEMP_PATH, np.array([T], dtype=np.float32))

    # Save artifacts
    joblib.dump(scaler, SCALER_PATH)
    torch.save(model.state_dict(), MODEL_PATH)

    # Final metrics on calib split
    model.eval()
    with torch.no_grad():
        logits = model(torch.tensor(Xc_s, dtype=torch.float32).to(device))
        preds = torch.argmax(logits, dim=1).cpu().numpy()
    metrics = {
        **{"cv_f1_macro": float(best_cv)},
        **{
            "calib_split": {
                "f1_macro": float(f1_score(y_cal, preds, average="macro")),
                "f1_weighted": float(f1_score(y_cal, preds, average="weighted")),
            }
        },
        "best_cfg": best_cfg,
        "temperature": float(T),
    }
    with open(METRICS_JSON, "w") as f:
        json.dump(metrics, f, indent=2)

    # Classification report & confusion matrix
    rep = classification_report(
        y_cal,
        preds,
        target_names=["Low", "Medium", "High", "Critical"],
        output_dict=True,
    )
    pd.DataFrame(rep).to_csv(CLF_CSV, index=True)

    try:
        import matplotlib.pyplot as plt

        cm = confusion_matrix(y_cal, preds, labels=[0, 1, 2, 3])
        fig = plt.figure()
        plt.imshow(cm, interpolation="nearest")
        plt.title("Confusion Matrix (calib split)")
        plt.colorbar()
        tick_marks = np.arange(4)
        plt.xticks(tick_marks, ["Low", "Medium", "High", "Critical"], rotation=45)
        plt.yticks(tick_marks, ["Low", "Medium", "High", "Critical"])
        plt.tight_layout()
        plt.ylabel("True")
        plt.xlabel("Predicted")
        fig.savefig(CM_PNG, bbox_inches="tight")
        plt.close(fig)
    except Exception:
        pass  # plotting optional

    print(f"[✓] Saved model → {MODEL_PATH}")
    print(f"[✓] Saved scaler → {SCALER_PATH}")
    print(f"[✓] Saved temperature → {TEMP_PATH}")
    print(f"[✓] Metrics → {METRICS_JSON}")
    print(f"[✓] Report → {CLF_CSV}")
    print(
        f"[i] CV macro-F1: {best_cv:.3f} | Calib split macro-F1: {metrics['calib_split']['f1_macro']:.3f} | T={T:.3f}"
    )


if __name__ == "__main__":
    main()
