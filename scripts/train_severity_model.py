# ******************************************************************************************
# scripts/train_severity_model.py
# Trains CVESeverityNet using CVRF XML data (allitems-cvrf.xml)
# ******************************************************************************************
import os
import sys
import torch
import joblib
import torch.nn as nn
import torch.optim as optim
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import xml.etree.ElementTree as ET

# Add CHARLOTTE root directory to sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Now you can import from models/cve_severity_predictor.py
from models.cve_severity_predictor import CVESeverityNet

# ==========================================================================================
# PARSE CVRF XML DATA
# ==========================================================================================
def parse_cvrf_xml(xml_path):
    """
    Parse CVRF XML to extract features and severity labels.
    Expected output: features (X) and severity labels (y)
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    X = []
    y = []

    for vuln in root.findall(".//{http://www.icasi.org/CVRF/schema/vuln/1.1}Vulnerability"):
        # Extract CVSS data (default to 0.0 if not present)
        cvss_base = float(vuln.findtext(".//{http://www.first.org/cvss/v3.0}BaseScore", default="0.0"))
        impact = float(vuln.findtext(".//{http://www.first.org/cvss/v3.0}ImpactScore", default="0.0"))
        exploitability = float(vuln.findtext(".//{http://www.first.org/cvss/v3.0}ExploitabilityScore", default="0.0"))

        # Heuristic: Check if remote attack vector (1 if remote, 0 otherwise)
        attack_vector = vuln.findtext(".//{http://www.first.org/cvss/v3.0}AttackVector", default="LOCAL").upper()
        is_remote = 1 if attack_vector == "NETWORK" else 0

        # CWE ID (convert to integer ID, default to 0)
        cwe_id = vuln.findtext(".//{http://www.mitre.org/cwe}CWE", default="0")
        try:
            cwe_id = int(cwe_id.split("-")[1]) if "-" in cwe_id else int(cwe_id)
        except ValueError:
            cwe_id = 0

        # Severity mapping
        severity = vuln.findtext(".//{http://www.first.org/cvss/v3.0}BaseSeverity", default="LOW").upper()
        severity_map = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        y_class = severity_map.get(severity, 0)

        X.append([cvss_base, impact, exploitability, is_remote, cwe_id])
        y.append(y_class)

    return np.array(X), np.array(y)

# ==========================================================================================
# LOAD DATA
# ==========================================================================================
xml_file = "data/allitems-cvrf.xml"
X, y = parse_cvrf_xml(xml_file)

print(f"[+] Parsed {len(X)} CVE entries from {xml_file}")

# Normalize input features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train/test split
X_train, X_val, y_train, y_val = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

# Convert to torch tensors
X_train = torch.tensor(X_train, dtype=torch.float32)
y_train = torch.tensor(y_train, dtype=torch.long)
X_val = torch.tensor(X_val, dtype=torch.float32)
y_val = torch.tensor(y_val, dtype=torch.long)

# ==========================================================================================
# TRAIN MODEL
# ==========================================================================================
model = CVESeverityNet()
criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=0.001)

for epoch in range(50):
    model.train()
    outputs = model(X_train)
    loss = criterion(outputs, y_train)

    optimizer.zero_grad()
    loss.backward()
    optimizer.step()

    if epoch % 10 == 0:
        model.eval()
        val_outputs = model(X_val)
        val_preds = torch.argmax(val_outputs, dim=1)
        acc = (val_preds == y_val).float().mean().item()
        print(f"Epoch {epoch} - Loss: {loss.item():.4f}, Val Acc: {acc:.4f}")

# ==========================================================================================
# SAVE MODEL + SCALER
# ==========================================================================================
os.makedirs("data/model_weights", exist_ok=True)
torch.save(model.state_dict(), "data/model_weights/severity_net.pt")
joblib.dump(scaler, "data/model_weights/scaler_severity.pkl")
print("[*] Model and scaler saved.")
