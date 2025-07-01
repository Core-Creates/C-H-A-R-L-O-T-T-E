
# ******************************************************************************************
# scripts/train_severity_model.py
# Trains CVESeverityNet using synthetic or real CVE data
# ******************************************************************************************

import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import os
import joblib
from models.cve_severity_predictor import CVESeverityNet

# Simulated dataset: 1000 CVEs with 5 features, 4 classes
X = np.random.rand(1000, 5)
y = np.random.randint(0, 4, size=(1000,))

# Normalize input features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train/test split
X_train, X_val, y_train, y_val = train_test_split(X_scaled, y, test_size=0.2)

# Convert to torch tensors
X_train = torch.tensor(X_train, dtype=torch.float32)
y_train = torch.tensor(y_train, dtype=torch.long)
X_val = torch.tensor(X_val, dtype=torch.float32)
y_val = torch.tensor(y_val, dtype=torch.long)

# Model
model = CVESeverityNet()
criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=0.001)

# Train loop
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

# Save model + scaler
os.makedirs("data/model_weights", exist_ok=True)
torch.save(model.state_dict(), "data/model_weights/severity_net.pt")
joblib.dump(scaler, "data/model_weights/scaler_severity.pkl")
print("[*] Model and scaler saved.")
