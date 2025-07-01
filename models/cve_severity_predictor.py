
# ******************************************************************************************
# models/cve_severity_predictor.py
# Neural network for predicting CVE severity class (Low, Medium, High, Critical)
# ******************************************************************************************

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from sklearn.preprocessing import StandardScaler
import os
import joblib

# ==========================================================================================
# CVESeverityNet: Feedforward Neural Network
# ==========================================================================================
class CVESeverityNet(nn.Module):
    def __init__(self, input_dim=5, hidden_dim=32, output_dim=4):
        super(CVESeverityNet, self).__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, 16)
        self.output = nn.Linear(16, output_dim)

    def forward(self, x):
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        return self.output(x)

# ==========================================================================================
# Model Utilities
# ==========================================================================================

def load_model(model_path="data/model_weights/severity_net.pt", input_dim=5):
    model = CVESeverityNet(input_dim=input_dim)
    if os.path.exists(model_path):
        model.load_state_dict(torch.load(model_path))
        model.eval()
    else:
        raise FileNotFoundError(f"[!] Model file not found at {model_path}")
    return model

def load_scaler(scaler_path="data/model_weights/scaler_severity.pkl"):
    if os.path.exists(scaler_path):
        return joblib.load(scaler_path)
    else:
        raise FileNotFoundError(f"[!] Scaler file not found at {scaler_path}")

def predict_severity(cve_features, model=None, scaler=None):
    """
    Predict CVE severity from 5 features:
    [cvss_base, cvss_impact, exploitability_score, is_remote, cwe_id]
    Returns: One of ["Low", "Medium", "High", "Critical"]
    """
    if model is None:
        model = load_model()
    if scaler is None:
        scaler = load_scaler()

    with torch.no_grad():
        x = np.array([cve_features])
        x_scaled = scaler.transform(x)
        tensor_input = torch.tensor(x_scaled, dtype=torch.float32)
        logits = model(tensor_input)
        pred = torch.argmax(logits, dim=1).item()
        return ["Low", "Medium", "High", "Critical"][pred]
