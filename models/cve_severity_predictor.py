# ******************************************************************************************
# models/cve_severity_predictor.py
# Neural network for predicting CVE severity class (Low, Medium, High, Critical)
# ******************************************************************************************

# ========================
# BEGINNING OF IMPORTS
# ========================

import os  # For file existence checks
import sys  # For modifying sys.path to include CHARLOTTE root directory
import torch  # PyTorch library for tensor computation and model handling
import joblib  # For loading saved scaler objects (StandardScaler from sklearn)
import pandas as pd  # For reading CSV files
import numpy as np  # For numerical operations, array, and matrix operations
import torch.nn as nn  # For building neural network layers
import torch.nn.functional as F  # Functional API for activations like ReLU
from sklearn.preprocessing import StandardScaler  # Used to normalize input features

# Add CHARLOTTE root directory to sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# ========================
# DEVICE CONFIGURATION
# ========================
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# ========================
# END OF IMPORTS
# ========================

# ==========================================================================================
# CLASS: CVESeverityNet
# A feedforward neural network for CVE severity classification
# ==========================================================================================
class CVESeverityNet(nn.Module):
    def __init__(self, input_dim=5, hidden_dim=32, output_dim=4):
        """
        Initializes a 3-layer feedforward neural network for severity classification.

        Args:
            input_dim (int): Number of input features (default: 5)
                - Typically includes: cvss_base, cvss_impact, exploitability_score, is_remote, cwe_id
            hidden_dim (int): Neuron count for the first hidden layer (default: 32)
            output_dim (int): Number of severity classes (Low, Medium, High, Critical) → 4
        """
        super(CVESeverityNet, self).__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, 16)
        self.output = nn.Linear(16, output_dim)

    def forward(self, x):
        """
        Defines the forward pass through the network.

        Args:
            x (Tensor): Input tensor of shape [batch_size, input_dim]

        Returns:
            Tensor: Raw logits of shape [batch_size, output_dim]
        """
        x = F.relu(self.fc1(x))   # First hidden layer with ReLU
        x = F.relu(self.fc2(x))   # Second hidden layer with ReLU
        return self.output(x)     # Output layer (logits, not softmaxed)


# ==========================================================================================
# FUNCTION: load_model
# Load the trained PyTorch model from disk
# ==========================================================================================
def load_model(model_path="data/model_weights/severity_net.pt", input_dim=5):
    """
    Loads the trained model and transfers it to GPU or CPU based on availability.
    """
    model = CVESeverityNet(input_dim=input_dim).to(DEVICE)
    if os.path.exists(model_path):
        model.load_state_dict(torch.load(model_path, map_location=DEVICE))
        model.eval()
    else:
        raise FileNotFoundError(f"[!] Model file not found at {model_path}")
    return model


# ==========================================================================================
# FUNCTION: load_scaler
# Load the StandardScaler used during training
# ==========================================================================================
def load_scaler(scaler_path="data/model_weights/scaler_severity.pkl"):
    """
    Loads the StandardScaler object used to normalize training data.

    Args:
        scaler_path (str): Path to saved .pkl file

    Returns:
        scaler (StandardScaler): Pre-fitted scaler
    """
    if os.path.exists(scaler_path):
        return joblib.load(scaler_path)
    else:
        raise FileNotFoundError(f"[!] Scaler file not found at {scaler_path}")


# ==========================================================================================
# FUNCTION: predict_severity
# Perform prediction using the trained model and normalized features
# ==========================================================================================
def predict_severity(cve_features, model=None, scaler=None):
    """
    Predicts the severity class of a CVE using a trained neural network.

    Args:
        cve_features (List[float]): Features: 
            [cvss_base, cvss_impact, exploitability_score, is_remote, cwe_id]
        model (CVESeverityNet): Optional pre-loaded model
        scaler (StandardScaler): Optional pre-loaded scaler

    Returns:
        str: One of ["Low", "Medium", "High", "Critical"]
    """
    if model is None:
        model = load_model()
    if scaler is None:
        scaler = load_scaler()

    with torch.no_grad():
        x = np.array([cve_features])
        x_scaled = scaler.transform(x)
        tensor_input = torch.tensor(x_scaled, dtype=torch.float32).to(DEVICE)

        logits = model(tensor_input)
        pred = torch.argmax(logits, dim=1).item()

        severity_classes = ["Low", "Medium", "High", "Critical"]
        return severity_classes[pred]


# ==========================================================================================
# FUNCTION: predict_batch
# Performs batch severity prediction for multiple CVEs (GPU-accelerated if available)
# ==========================================================================================
def predict_batch(cve_feature_list, model=None, scaler=None):
    """
    Performs batch prediction of CVE severity levels.

    Args:
        cve_feature_list (List[List[float]]): A list of CVE records, where each record is a
            list of 5 features: [cvss_base, cvss_impact, exploitability_score, is_remote, cwe_id]
        model (CVESeverityNet): Optional pre-loaded model
        scaler (StandardScaler): Optional pre-loaded scaler

    Returns:
        List[str]: List of predicted severity classes for each CVE record
            Each label is one of: ["Low", "Medium", "High", "Critical"]
    """
    if model is None:
        model = load_model()
    if scaler is None:
        scaler = load_scaler()

    with torch.no_grad():
        # Convert input to NumPy array for batch processing
        x = np.array(cve_feature_list)

        # Normalize using pre-fitted scaler
        x_scaled = scaler.transform(x)

        # Convert to PyTorch tensor and move to correct device
        tensor_input = torch.tensor(x_scaled, dtype=torch.float32).to(DEVICE)

        # Run batch through the model
        logits = model(tensor_input)

        # Get predicted class index for each row in batch
        preds = torch.argmax(logits, dim=1).cpu().numpy()

        # Map indices to human-readable severity classes
        severity_classes = ["Low", "Medium", "High", "Critical"]
        return [severity_classes[i] for i in preds]
# ==========================================================================================
# END OF FUNCTION: predict_batch
# ==========================================================================================



# ******************************************************************************************
# END OF models/cve_severity_predictor.py
# ******************************************************************************************
