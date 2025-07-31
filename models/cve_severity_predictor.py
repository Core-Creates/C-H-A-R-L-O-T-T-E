# ******************************************************************************************
# models/cve_severity_predictor.py
# Neural network for predicting CVE severity class (Low, Medium, High, Critical)
# ******************************************************************************************

# ========================
# BEGINNING OF IMPORTS
# ========================

import os  # For file existence checks
import torch  # PyTorch library for tensor computation and model handling
import torch.nn as nn  # For building neural network layers
import torch.nn.functional as F  # Functional API for activations like ReLU
import numpy as np  # For array and matrix operations
import joblib  # For loading saved scaler objects (StandardScaler from sklearn)
from sklearn.preprocessing import StandardScaler  # Used to normalize input features

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
    Loads the trained model from a .pt file and returns it.

    Args:
        model_path (str): Path to saved model weights
        input_dim (int): Number of input features (default: 5)

    Returns:
        model (nn.Module): Loaded and ready-to-use PyTorch model
    """
    model = CVESeverityNet(input_dim=input_dim)
    if os.path.exists(model_path):
        model.load_state_dict(torch.load(model_path))
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
        cve_features (List[float]): Input features: 
            [cvss_base, cvss_impact, exploitability_score, is_remote, cwe_id]
        model (CVESeverityNet): Optional pre-loaded model instance
        scaler (StandardScaler): Optional pre-loaded scaler

    Returns:
        str: Severity class: one of ["Low", "Medium", "High", "Critical"]
    """
    # Load model and scaler if not passed in
    if model is None:
        model = load_model()
    if scaler is None:
        scaler = load_scaler()

    with torch.no_grad():
        # Convert input to 2D NumPy array, then scale
        x = np.array([cve_features])
        x_scaled = scaler.transform(x)

        # Convert scaled input to PyTorch tensor
        tensor_input = torch.tensor(x_scaled, dtype=torch.float32)

        # Feed input to the model
        logits = model(tensor_input)

        # Take the highest scoring index
        pred = torch.argmax(logits, dim=1).item()

        # Severity class mapping
        severity_classes = ["Low", "Medium", "High", "Critical"]
        return severity_classes[pred]

# ******************************************************************************************
# END OF models/cve_severity_predictor.py
# ******************************************************************************************
