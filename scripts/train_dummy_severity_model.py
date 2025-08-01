# scripts/train_dummy_severity_model.py

import os
import sys
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from sklearn.preprocessing import StandardScaler
import joblib

# Add CHARLOTTE root directory to sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
    
# Now you can import from models/cve_severity_predictor.py
from models.cve_severity_predictor import CVESeverityNet

# Create dummy dataset with 5 features and 4 class labels
X = np.random.rand(500, 5)
y = np.random.randint(0, 4, size=500)

# Normalize the input features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Convert to PyTorch tensors
X_tensor = torch.tensor(X_scaled, dtype=torch.float32)
y_tensor = torch.tensor(y, dtype=torch.long)

# Instantiate model
model = CVESeverityNet(input_dim=5)

# Training setup
criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.parameters(), lr=0.01)

# Train the model (very basic 10-epoch run)
for epoch in range(10):
    optimizer.zero_grad()
    outputs = model(X_tensor)
    loss = criterion(outputs, y_tensor)
    loss.backward()
    optimizer.step()
    print(f"Epoch {epoch+1}/10 - Loss: {loss.item():.4f}")

# Save model and scaler
os.makedirs("data/model_weights", exist_ok=True)
torch.save(model.state_dict(), "data/model_weights/severity_net.pt")
joblib.dump(scaler, "data/model_weights/scaler_severity.pkl")

print("[+] Dummy model and scaler saved to data/model_weights/")
