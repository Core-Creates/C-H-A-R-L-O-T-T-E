#!/usr/bin/env python3
# ******************************************************************************************
# cve_severity_train_all.py
# One-stop script to train, calibrate (temperature scaling), and evaluate the
# CVE severity classifier used by models/cve_severity_predictor.py.
#
# Features:
# - Load features/labels from CSVs (defaults to data/parsed/features.csv & labels.csv).
# - Train either the baseline CVESeverityNet or a stronger BetterNet.
# - Optional cross-validated hyperparameter selection (balanced class weights).
# - Save artifacts: model weights, scaler, temperature.
# - Produce metrics, classification report, and optional confusion matrix image.
# - Evaluate on a provided dataset or the training split.
#
# Usage examples:
#   Train (quick):   python cve_severity_train_all.py train --features data/parsed/features.csv --labels data/parsed/labels.csv
#   Train (better):  python cve_severity_train_all.py train --model better --cv --epochs 80
#   Evaluate:        python cve_severity_train_all.py eval  --features data/parsed/features.csv --labels data/parsed/labels.csv
#
# Artifacts are saved under data/model_weights and reports under data/reports by default.
# ******************************************************************************************

import sys
import json
import argparse
import numpy as np
import pandas as pd
import joblib
from pathlib import Path

import torch
import torch.nn as nn
from torch.utils.data import TensorDataset, DataLoader

from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score, classification_report, confusion_matrix

# Project root & imports -------------------------------------------------------------------
HERE = Path(__file__).parent.resolve()
ROOT_DIR = HERE  # allow placing this script anywhere; relative paths resolved from CWD
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# Try importing the project model; fall back if layout differs
try:
    from models.cve_severity_predictor import CVESeverityNet, DEVICE, LABELS  # type: ignore
except Exception:
    # Minimal fallback definition if running standalone without repo layout
    DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    LABELS = ["Low", "Medium", "High", "Critical"]

    class CVESeverityNet(nn.Module):
        def __init__(self, input_dim=5, hidden_dim=32, output_dim=4):
            super().__init__()
            self.fc1 = nn.Linear(input_dim, hidden_dim)
            self.fc2 = nn.Linear(hidden_dim, 16)
            self.output = nn.Linear(16, output_dim)

        def forward(self, x):
            x = torch.relu(self.fc1(x))
            x = torch.relu(self.fc2(x))
            return self.output(x)


# Paths & output dirs ----------------------------------------------------------------------
DATA_DIR = Path("data")
PARSED_DIR = DATA_DIR / "parsed"
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


# Better model -----------------------------------------------------------------------------
class BetterNet(nn.Module):
    """A stronger network with BN + Dropout; matches scripts/train_severity_accurate.py intent."""

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


# Utilities --------------------------------------------------------------------------------
SEED = 1337
np.random.seed(SEED)
torch.manual_seed(SEED)


def coerce_labels(y_raw) -> np.ndarray:
    """Accept ints 0..3 or strings: low/medium/high/critical."""
    mapping = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    out = []
    for v in y_raw:
        if pd.isna(v):
            out.append(1)
            continue
        try:
            iv = int(float(v))
            if iv in (0, 1, 2, 3):
                out.append(iv)
                continue
        except Exception:
            pass
        out.append(mapping.get(str(v).strip().lower(), 1))
    return np.array(out, dtype=int)


def class_weights(y: np.ndarray) -> torch.Tensor:
    # inverse-frequency normalized
    classes, counts = np.unique(y, return_counts=True)
    freq = counts / counts.sum()
    w = 1.0 / np.clip(freq, 1e-6, None)
    w = w / np.mean(w)
    full = np.ones(4, dtype=float)
    for c, val in zip(classes, w):
        if 0 <= c <= 3:
            full[c] = val
    return torch.tensor(full, dtype=torch.float32)


def load_features_labels(features_path: str | None, labels_path: str | None):
    # Resolve features ---------------------------------------------------------
    if features_path:
        X_path = Path(features_path)
    else:
        X_path = PARSED_DIR / "features.csv"
        if not X_path.exists():
            alt = DATA_DIR / "features.csv"
            X_path = alt
    if not X_path.exists():
        raise FileNotFoundError(f"Features not found at {X_path}. Provide --features.")
    X = pd.read_csv(X_path).values

    # Resolve labels -----------------------------------------------------------
    if labels_path:
        ydf = pd.read_csv(Path(labels_path))
    else:
        # try parsed/labels.csv -> data/labels.csv -> data/charlotte_labels.csv
        for p in [
            PARSED_DIR / "labels.csv",
            DATA_DIR / "labels.csv",
            DATA_DIR / "charlotte_labels.csv",
        ]:
            if p.exists():
                ydf = pd.read_csv(p)
                break
        else:
            raise FileNotFoundError("Could not find labels.csv; provide --labels.")
    y = coerce_labels(ydf.iloc[:, 0].values)

    if len(y) != len(X):
        raise ValueError(f"Features/labels length mismatch: X={len(X)}, y={len(y)}")

    return X, y, X_path, Path(labels_path) if labels_path else None


def fit_once(
    X_tr,
    y_tr,
    X_va,
    y_va,
    device,
    model_kind="basic",
    epochs=60,
    batch=256,
    lr=3e-4,
    wd=1e-2,
    use_class_weights=True,
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

    if model_kind == "better":
        model = BetterNet(input_dim=X_tr.shape[1]).to(device)
    else:
        model = CVESeverityNet(input_dim=X_tr.shape[1]).to(device)

    cw = class_weights(y_tr).to(device) if use_class_weights else None
    crit = nn.CrossEntropyLoss(weight=cw)
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=wd)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=max(epochs, 1))

    best_f1, best_state = -1.0, None
    patience, no_improve = 10, 0

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

        # Validate
        model.eval()
        preds, ys = [], []
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

    model.load_state_dict(best_state)
    return model, scaler, best_f1


def find_temperature(model, Xc_s, y_cal, device) -> float:
    temp = torch.tensor(1.0, requires_grad=True, device=device)
    opt = torch.optim.LBFGS([temp], lr=0.1, max_iter=50)
    nll = nn.CrossEntropyLoss()

    with torch.no_grad():
        logits_val = model(torch.tensor(Xc_s, dtype=torch.float32).to(device))

    def closure():
        opt.zero_grad()
        loss = nll(
            logits_val / temp, torch.tensor(y_cal, dtype=torch.long, device=device)
        )
        loss.backward()
        return loss

    opt.step(closure)
    return float(temp.detach().cpu().item())


# Commands ---------------------------------------------------------------------------------
def cmd_train(args):
    device = (
        DEVICE
        if "DEVICE" in globals()
        else torch.device("cuda" if torch.cuda.is_available() else "cpu")
    )
    X, y, X_path, _ = load_features_labels(args.features, args.labels)

    # Quick split for calibration set used for temperature scaling
    X_train_all, X_cal, y_train_all, y_cal = train_test_split(
        X, y, test_size=args.calib_size, random_state=SEED, stratify=y
    )

    # Either do CV search or a single fit
    if args.cv:
        skf = StratifiedKFold(n_splits=args.cv_folds, shuffle=True, random_state=SEED)
        search = [
            {"epochs": args.epochs, "batch": args.batch, "lr": args.lr, "wd": args.wd},
            {
                "epochs": max(args.epochs - 20, 20),
                "batch": args.batch,
                "lr": args.lr * 1.5,
                "wd": args.wd,
            },
            {
                "epochs": max(args.epochs + 20, 40),
                "batch": args.batch,
                "lr": max(args.lr * 0.7, 1e-5),
                "wd": args.wd / 2,
            },
        ]
        best_cfg, best_cv = None, -1.0
        for cfg in search:
            scores = []
            for tr_idx, va_idx in skf.split(X_train_all, y_train_all):
                model, scaler, f1m = fit_once(
                    X_train_all[tr_idx],
                    y_train_all[tr_idx],
                    X_train_all[va_idx],
                    y_train_all[va_idx],
                    device,
                    model_kind=args.model,
                    use_class_weights=not args.no_class_weights,
                    **cfg,
                )
                scores.append(f1m)
            mean_score = float(np.mean(scores))
            print(f"[cv] {cfg} macro-F1={mean_score:.3f}")
            if mean_score > best_cv:
                best_cv, best_cfg = mean_score, cfg
        print(f"[cv] Best config: {best_cfg} (macro-F1={best_cv:.3f})")
        use_cfg = best_cfg
    else:
        use_cfg = {
            "epochs": args.epochs,
            "batch": args.batch,
            "lr": args.lr,
            "wd": args.wd,
        }

    # Final fit on train_all vs calib
    model, scaler, f1m = fit_once(
        X_train_all,
        y_train_all,
        X_cal,
        y_cal,
        device,
        model_kind=args.model,
        use_class_weights=not args.no_class_weights,
        **use_cfg,
    )

    # Temperature scaling
    Xc_s = scaler.transform(X_cal)
    T = 1.0
    if not args.no_temp:
        T = find_temperature(model, Xc_s, y_cal, device)

    # Save artifacts
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    REP_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(scaler, SCALER_PATH)
    torch.save(model.state_dict(), MODEL_PATH)
    np.save(TEMP_PATH, np.array([T], dtype=np.float32))

    # Evaluate on calib split for a quick sanity check
    model.eval()
    with torch.no_grad():
        logits = model(torch.tensor(Xc_s, dtype=torch.float32).to(device))
        logits = logits / T
        preds = torch.argmax(logits, dim=1).cpu().numpy()

    metrics = {
        "cv_used": bool(args.cv),
        "cv_f1_macro": None if not args.cv else float(best_cv),
        "calib": {
            "f1_macro": float(f1_score(y_cal, preds, average="macro")),
            "f1_weighted": float(f1_score(y_cal, preds, average="weighted")),
        },
        "temperature": float(T),
        "model": args.model,
        "config": use_cfg,
        "features_path": str(X_path),
    }
    with open(METRICS_JSON, "w") as f:
        json.dump(metrics, f, indent=2)

    # Save classification report and confusion matrix (robust to missing classes)
    rep = classification_report(
        y_cal,
        preds,
        labels=[0, 1, 2, 3],
        target_names=LABELS,
        output_dict=True,
        zero_division=0,
    )
    pd.DataFrame(rep).to_csv(CLF_CSV, index=True)
    try:
        import matplotlib.pyplot as plt

        cm = confusion_matrix(y_cal, preds, labels=[0, 1, 2, 3])
        fig = plt.figure()
        plt.imshow(cm, interpolation="nearest")
        plt.title("Confusion Matrix (calibration split)")
        plt.colorbar()
        tick_marks = np.arange(4)
        plt.xticks(tick_marks, LABELS, rotation=45)
        plt.yticks(tick_marks, LABELS)
        plt.tight_layout()
        plt.ylabel("True label")
        plt.xlabel("Predicted label")
        fig.savefig(CM_PNG, bbox_inches="tight")
        plt.close(fig)
    except Exception:
        pass

    print(f"[✓] Saved model → {MODEL_PATH}")
    print(f"[✓] Saved scaler → {SCALER_PATH}")
    print(f"[✓] Saved temperature → {TEMP_PATH}")
    print(f"[✓] Metrics → {METRICS_JSON}")
    print(f"[✓] Report → {CLF_CSV}")


def cmd_eval(args):
    device = (
        DEVICE
        if "DEVICE" in globals()
        else torch.device("cuda" if torch.cuda.is_available() else "cpu")
    )
    # Load artifacts
    scaler = joblib.load(SCALER_PATH)
    T = float(np.load(TEMP_PATH)[0]) if TEMP_PATH.exists() else 1.0
    # Build model & load weights
    model = CVESeverityNet(input_dim=5).to(device)
    model.load_state_dict(torch.load(MODEL_PATH, map_location=device))
    model.eval()

    # Load data for evaluation
    X, y, *_ = load_features_labels(args.features, args.labels)
    Xs = scaler.transform(X)

    with torch.no_grad():
        logits = model(torch.tensor(Xs, dtype=torch.float32).to(device))
        logits = logits / T
        preds = torch.argmax(logits, dim=1).cpu().numpy()

    rep_txt = classification_report(
        y, preds, labels=[0, 1, 2, 3], target_names=LABELS, zero_division=0
    )
    print(rep_txt)


# CLI -------------------------------------------------------------------------------------
def build_argparser():
    p = argparse.ArgumentParser(description="Train / Evaluate CVE severity classifier")
    sub = p.add_subparsers(dest="cmd", required=True)

    # Train
    t = sub.add_parser("train", help="Train model and save artifacts")
    t.add_argument("--features", type=str, default="", help="Path to features.csv")
    t.add_argument("--labels", type=str, default="", help="Path to labels.csv")
    t.add_argument("--model", choices=["basic", "better"], default="basic")
    t.add_argument("--epochs", type=int, default=60)
    t.add_argument("--batch", type=int, default=256)
    t.add_argument("--lr", type=float, default=3e-4)
    t.add_argument("--wd", type=float, default=1e-2)
    t.add_argument(
        "--no-class-weights", action="store_true", help="Disable class weighting"
    )
    t.add_argument(
        "--cv", action="store_true", help="Enable 5-fold CV hyperparam search"
    )
    t.add_argument("--cv-folds", type=int, default=5)
    t.add_argument(
        "--calib-size",
        type=float,
        default=0.15,
        help="Calibration split size for temp scaling",
    )
    t.add_argument("--no-temp", action="store_true", help="Skip temperature scaling")
    t.set_defaults(func=cmd_train)

    # Eval
    e = sub.add_parser("eval", help="Evaluate saved artifacts against a dataset")
    e.add_argument("--features", type=str, default="", help="Path to features.csv")
    e.add_argument("--labels", type=str, default="", help="Path to labels.csv")
    e.set_defaults(func=cmd_eval)

    return p


def main():
    ap = build_argparser()
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
