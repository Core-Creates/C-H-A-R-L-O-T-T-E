# ******************************************************************************************
# models/cve_severity_predictor.py
# Neural network for predicting CVE severity class (Low, Medium, High, Critical)
# ******************************************************************************************

# PyTorch library for deep learning
import torch
import torch.nn as nn
import torch.nn.functional as F  # Functional interface for activations like ReLU
import numpy as np  # Numerical operations for array/matrix handling
from sklearn.preprocessing import StandardScaler  # For input feature normalization
import os  # For file existence checks
import joblib  # For loading the saved scaler object

# ==========================================================================================
# CVESeverityNet: Feedforward Neural Network
# This class defines the structure of the model used for severity prediction.
# ==========================================================================================
class CVESeverityNet(nn.Module):
    def __init__(self, input_dim=5, hidden_dim=32, output_dim=4):
        """
        Initialize the network layers.
        input_dim: number of input features (e.g., 5 CVE attributes):
            - input_dim=5 meaning the model expects 5 input features.
            - It represents the number of input features the model expects. 
            - For the CVE severity model, this could correspond to:
                - cvss_base
                - cvss_impact
                - exploitability_score
                - is_remote
                - cwe_id
        hidden_dim: number of neurons in the first hidden layer
            - hidden_dim=32 means the first hidden layer has 32 neurons.
            - This is a hyperparameter you can tune to affect model performance.
        output_dim: number of output classes (4 severity levels)
            - output_dim=4 means the model outputs logits for 4 classes: Low, Medium, High, Critical.
            
        """
        super(CVESeverityNet, self).__init__()
        self.fc1 = nn.Linear(input_dim, hidden_dim)  # First hidden layer
        self.fc2 = nn.Linear(hidden_dim, 16)         # Second hidden layer with 16 neurons
        self.output = nn.Linear(16, output_dim)      # Output layer for 4 severity levels

    def forward(self, x):
        """
        Define the forward pass of the network.
        Applies ReLU activation after each hidden layer.
        Returns raw logits (not softmaxed) for classification.
        """
        x = F.relu(self.fc1(x))  # First layer with ReLU activation
        x = F.relu(self.fc2(x))  # Second layer with ReLU activation
        return self.output(x)    # Output layer (logits for classification)

# ==========================================================================================
# Model Utilities: Load model and scaler, perform prediction
# ==========================================================================================

def load_model(model_path="data/model_weights/severity_net.pt", input_dim=5):
    """
    Loads the trained PyTorch model from disk.
    If the file does not exist, raise an error.
    """
    model = CVESeverityNet(input_dim=input_dim)  # Instantiate model with input dimensions
    if os.path.exists(model_path):
        model.load_state_dict(torch.load(model_path))  # Load learned weights into model
        model.eval()  # Set model to evaluation mode (disables dropout, etc.)
    else:
        raise FileNotFoundError(f"[!] Model file not found at {model_path}")
    return model

def load_scaler(scaler_path="data/model_weights/scaler_severity.pkl"):
    """
    Loads the pre-fitted StandardScaler used to normalize input features.
    Ensures consistency between training and prediction data distributions.
    """
    if os.path.exists(scaler_path):
        return joblib.load(scaler_path)  # Load saved scaler object
    else:
        raise FileNotFoundError(f"[!] Scaler file not found at {scaler_path}")

def predict_severity(cve_features, model=None, scaler=None):
    """
    Predicts the severity class of a CVE using a trained model.
    
    Parameters:
    - cve_features: list of 5 numerical features [cvss_base, cvss_impact, exploitability_score, is_remote, cwe_id]
    - model: pre-loaded PyTorch model (optional)
    - scaler: pre-loaded StandardScaler object (optional)
    
    Returns:
    - A severity class string: one of ["Low", "Medium", "High", "Critical"]
    """
    # Load model and scaler if not provided by caller
    if model is None:
        model = load_model()
    if scaler is None:
        scaler = load_scaler()

    with torch.no_grad():  # Disable gradient tracking for inference (faster and memory-efficient)
        x = np.array([cve_features])  # Convert input to NumPy array and wrap in outer list for batching
        x_scaled = scaler.transform(x)  # Normalize input using fitted scaler
        tensor_input = torch.tensor(x_scaled, dtype=torch.float32)  # Convert to PyTorch tensor
        logits = model(tensor_input)  # Run input through the model to get raw scores (logits)
        pred = torch.argmax(logits, dim=1).item()  # Take index of highest score as prediction
        return ["Low", "Medium", "High", "Critical"][pred]  # Map class index to human-readable label
