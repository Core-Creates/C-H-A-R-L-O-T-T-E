# ******************************************************************************************
# scripts/train_severity_model.py
# Trains CVESeverityNet using pre-parsed CVE data from CSVs
# This script expects:
#   - data/parsed/features.csv
#   - data/parsed/labels.csv
# These can be generated using: python utils/parse_cvrf.py data/allitems-cvrf.xml
# ******************************************************************************************

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import os
import sys
import joblib

# Add CHARLOTTE root directory to sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Now you can import from models/cve_severity_predictor.py
from models.cve_severity_predictor import CVESeverityNet

# ==========================================================================================
# STEP 1: LOAD PRE-PARSED CVE DATA FROM CSV FILES
# ==========================================================================================

# Paths to preprocessed feature and label files
FEATURES_CSV = "data/parsed/features.csv"
LABELS_CSV = "data/parsed/labels.csv"

# Load feature vectors (X) and severity class labels (y)
print("[*] Loading parsed CVE features and labels from CSV...")
X = pd.read_csv(FEATURES_CSV).values  # Shape: [n_samples, 5]
y = pd.read_csv(LABELS_CSV).values.ravel()  # Shape: [n_samples] as a flat array

print(f"[+] Loaded {X.shape[0]} CVE entries with {X.shape[1]} features.")

# ==========================================================================================
# STEP 2: NORMALIZE FEATURES
# ==========================================================================================

# Standardize input features to zero mean and unit variance
# This is critical so the model can train efficiently without large variance in inputs
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ==========================================================================================
# STEP 3: SPLIT INTO TRAINING AND VALIDATION SETS
# ==========================================================================================

# Split the data into training and validation sets (80% train / 20% val)
X_train, X_val, y_train, y_val = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y  # Maintain class balance
)

# Convert data to PyTorch tensors for model training
X_train = torch.tensor(X_train, dtype=torch.float32)
y_train = torch.tensor(y_train, dtype=torch.long)
X_val = torch.tensor(X_val, dtype=torch.float32)
y_val = torch.tensor(y_val, dtype=torch.long)

# ==========================================================================================
# STEP 4: DEFINE MODEL, LOSS FUNCTION, OPTIMIZER
# ==========================================================================================

# Initialize model with:
#   - 5 input features (from CSV)
#   - 32 hidden units (adjustable)
#   - 4 output classes (Low, Medium, High, Critical)
model = CVESeverityNet(input_dim=5)

# Define loss function: CrossEntropyLoss is standard for multi-class classification
criterion = nn.CrossEntropyLoss()

# Use Adam optimizer for fast and adaptive learning
optimizer = optim.Adam(model.parameters(), lr=0.001)

# ==========================================================================================
# STEP 5: TRAINING LOOP
# ==========================================================================================

print("[*] Starting training loop...")
for epoch in range(50):  # Train for 50 epochs
    model.train()  # Enable training mode (for layers like dropout, if any)

    # Forward pass and compute training loss
    outputs = model(X_train)
    loss = criterion(outputs, y_train)

    # Backward pass and optimizer step
    optimizer.zero_grad()
    loss.backward()
    optimizer.step()

    # Validation step every 10 epochs to monitor generalization
    if epoch % 10 == 0:
        model.eval()
        val_outputs = model(X_val)
        val_preds = torch.argmax(val_outputs, dim=1)
        acc = (val_preds == y_val).float().mean().item()
        print(f"Epoch {epoch} - Loss: {loss.item():.4f}, Val Acc: {acc:.4f}")

# ==========================================================================================
# STEP 6: SAVE TRAINED MODEL AND SCALER
# ==========================================================================================

# Ensure output directory exists
os.makedirs("data/model_weights", exist_ok=True)

# Save model weights (PyTorch format) and scaler object (joblib)
torch.save(model.state_dict(), "data/model_weights/severity_net.pt")
joblib.dump(scaler, "data/model_weights/scaler_severity.pkl")

print("[✓] Training complete. Model and scaler saved to data/model_weights/")
print("[✓] You can now use the model to predict CVE severity classes.")

# ==========================================================================================
# END OF TRAINING SCRIPT
# ==========================================================================================
# You can now use the trained model to predict severity classes for new CVE data.
# Simply load the model and scaler, normalize your input features, and call predict_severity()
# from models/cve_severity_predictor.py with the normalized features.
# ==========================================================================================
