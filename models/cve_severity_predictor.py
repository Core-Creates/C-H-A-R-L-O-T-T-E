# ******************************************************************************************
# models/cve_severity_predictor.py
# Neural network for predicting CVE severity class (Low, Medium, High, Critical)
# ******************************************************************************************

import os
import sys
import torch
import joblib
import numpy as np
import torch.nn as nn
import torch.nn.functional as F
from collections.abc import Sequence

# Add CHARLOTTE root directory to sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Device configuration
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# Class labels (index-aligned with model outputs)
LABELS = ["Low", "Medium", "High", "Critical"]


# ==========================================================================================
# CLASS: CVESeverityNet
# ==========================================================================================
class CVESeverityNet(nn.Module):
    def __init__(self, input_dim: int = 5, hidden_dim: int = 32, output_dim: int = 4):
        """
        Initializes a 3-layer feedforward neural network for severity classification.

        Args:
            input_dim (int): Number of input features (default: 5)
                - Typically includes: cvss_base, cvss_impact, exploitability_score, is_remote, cwe_id
            hidden_dim (int): Hidden width (default: 32)
            output_dim (int): Number of severity classes (Low, Medium, High, Critical) → 4
        """
        super().__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, 16)
        self.output = nn.Linear(16, output_dim)

    def forward(self, x):
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        return self.output(x)


# ==========================================================================================
# FUNCTION: load_model
# ==========================================================================================
def load_model(
    model_path: str = "data/model_weights/severity_net.pt", input_dim: int = 5
) -> CVESeverityNet:
    """Loads the trained model and transfers it to GPU or CPU based on availability."""
    model = CVESeverityNet(input_dim=input_dim).to(DEVICE)
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"[!] Model file not found at {model_path}")
    model.load_state_dict(torch.load(model_path, map_location=DEVICE))
    model.eval()
    return model


# ==========================================================================================
# FUNCTION: load_scaler
# ==========================================================================================
def load_scaler(scaler_path: str = "data/model_weights/scaler_severity.pkl"):
    """Loads the StandardScaler object used to normalize training data."""
    if not os.path.exists(scaler_path):
        raise FileNotFoundError(f"[!] Scaler file not found at {scaler_path}")
    return joblib.load(scaler_path)


# ==========================================================================================
# FUNCTION: predict_severity
# ==========================================================================================
def predict_severity(
    cve_features: Sequence[float], model: CVESeverityNet = None, scaler=None
) -> str:
    """Predicts the severity class of a CVE using a trained neural network."""
    if model is None:
        model = load_model()
    if scaler is None:
        scaler = load_scaler()

    with torch.no_grad():
        x = np.array([list(cve_features)], dtype=float)
        x_scaled = scaler.transform(x)
        tensor_input = torch.tensor(x_scaled, dtype=torch.float32).to(DEVICE)
        logits = model(tensor_input)
        pred = torch.argmax(logits, dim=1).item()
        return LABELS[pred]


# ==========================================================================================
# FUNCTION: predict_batch
# ==========================================================================================
def predict_batch(
    cve_feature_list: list[Sequence[float]],
    model: CVESeverityNet = None,
    scaler=None,
    return_probs: bool = False,
) -> list[str] | dict[str, list]:
    """
    Performs batch prediction of CVE severity levels.

    By default returns a list of predicted labels.
    If return_probs=True, returns {"labels": [...], "probs": [[...], ...]} with softmax probabilities.
    """
    if model is None:
        model = load_model()
    if scaler is None:
        scaler = load_scaler()

    with torch.no_grad():
        x = np.array(cve_feature_list, dtype=float)
        x_scaled = scaler.transform(x)
        tensor_input = torch.tensor(x_scaled, dtype=torch.float32).to(DEVICE)
        logits = model(tensor_input)
        preds = torch.argmax(logits, dim=1).cpu().numpy()
        labels = np.take(LABELS, preds).tolist()
        if return_probs:
            probs = torch.softmax(logits, dim=1).cpu().numpy().tolist()
            return {"labels": labels, "probs": probs}
        return labels


# ==========================================================================================
# FUNCTION: safe_predict_severity
# ==========================================================================================
def safe_predict_severity(cve_features: Sequence[float]) -> str:
    """Wrapper that falls back to a simple heuristic when model/scaler files are missing."""
    try:
        return predict_severity(cve_features)
    except Exception:
        cvss_base, cvss_impact, exploitability, is_remote, cwe_id = list(cve_features)
        score = (
            0.5 * float(cvss_base)
            + 0.3 * float(cvss_impact)
            + 0.2 * float(exploitability)
        )
        if is_remote:
            score += 0.3
        if score >= 8.5:
            return "Critical"
        if score >= 6.5:
            return "High"
        if score >= 4.0:
            return "Medium"
        return "Low"


# ==========================================================================================
# FUNCTION: features_from_dataset_row
# ==========================================================================================
def features_from_dataset_row(row: dict) -> list[float]:
    """Map a CHARLOTTE triage dataset row (CSV/JSONL) to the 5-feature vector expected by the model."""
    cvss_base = float(row.get("severity", 3)) / 5.0 * 10.0  # map 1..5 → 2..10 approx
    cvss_impact = float(row.get("evidence_score", 50)) / 10.0  # 0..100 → 0..10
    exploitability = (
        7.5
        if str(row.get("protocol", "")).upper() in ("HTTP", "HTTPS", "RDP", "SSH")
        else 5.0
    )
    is_remote = (
        1.0 if str(row.get("src_geo", "")).upper() not in ("LOCAL", "INTERNAL") else 0.0
    )
    cwe_id = float(
        "".join(ch for ch in str(row.get("mitre_technique_id", "")) if ch.isdigit())
        or 79
    )
    return [cvss_base, cvss_impact, exploitability, is_remote, cwe_id]


# ******************************************************************************************
# END OF models/cve_severity_predictor.py
# ******************************************************************************************
