# utils/file_tools.py
# Utility functions for file operations in C.H.A.R.L.O.T.T.E.
# ******************************************************************************************
# This module provides helper functions for file and directory management.
# ******************************************************************************************

import os
import sys
import torch
import joblib
import shutil
import torch.nn as nn
from flask.ctx import F
import torch.optim as optim

# Add CHARLOTTE root directory to sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Import the CVESeverityNet model for loading
from models.cve_severity_predictor import CVESeverityNet

# ==========================================================================================
# FUNCTION: ensure_dir_exists
# Ensure a directory exists, creating it if necessary

def ensure_dir_exists(directory):
    """
    Ensure that a directory exists. If it does not, create it.

    Args:
        directory (str): Path to the directory to check/create.
    """
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"[+] Created directory: {directory}")
    else:
        print(f"[i] Directory already exists: {directory}")

# ==========================================================================================

# FUNCTION: ensure_file_exists
# Ensure a file exists, creating an empty file if it does not
def ensure_file_exists(file_path):
    """
    Ensure that a file exists. If it does not, create an empty file.

    Args:
        file_path (str): Path to the file to check/create.
    """
    if not os.path.isfile(file_path):
        with open(file_path, 'w') as f:
            pass  # Create an empty file
        print(f"[+] Created file: {file_path}")
    else:
        print(f"[i] File already exists: {file_path}")

# ==========================================================================================
# FUNCTION: get_file_size
# Get the size of a file in bytes
# ==========================================================================================
def get_file_size(file_path):
    """
    Get the size of a file in bytes.

    Args:
        file_path (str): Path to the file.

    Returns:
        int: Size of the file in bytes, or -1 if the file does not exist.
    """
    if os.path.isfile(file_path):
        return os.path.getsize(file_path)
    else:
        print(f"[!] File not found: {file_path}")
        return -1
# ==========================================================================================
# FUNCTION: list_files_in_directory
# List all files in a directory
# ==========================================================================================
def list_files_in_directory(directory):
    """
    List all files in a directory.

    Args:
        directory (str): Path to the directory.

    Returns:
        list: List of file names in the directory, or an empty list if the directory does not exist.
    """
    if os.path.isdir(directory):
        return os.listdir(directory)
    else:
        print(f"[!] Directory not found: {directory}")
        return []
# ==========================================================================================
# FUNCTION: delete_file
# Delete a file if it exists
# ==========================================================================================
def delete_file(file_path):
    """
    Delete a file if it exists.

    Args:
        file_path (str): Path to the file to delete.
    """
    if os.path.isfile(file_path):
        os.remove(file_path)
        print(f"[+] Deleted file: {file_path}")
    else:
        print(f"[!] File not found: {file_path}")
# ==========================================================================================
# FUNCTION: delete_directory
# Delete a directory and all its contents
# ==========================================================================================
def delete_directory(directory):
    """
    Delete a directory and all its contents.

    Args:
        directory (str): Path to the directory to delete.
    """
    if os.path.isdir(directory):
        import shutil
        shutil.rmtree(directory)
        print(f"[+] Deleted directory: {directory}")
    else:
        print(f"[!] Directory not found: {directory}")
# ==========================================================================================
# FUNCTION: get_absolute_path
# Get the absolute path of a file or directory
# ==========================================================================================
def get_absolute_path(path):
    """
    Get the absolute path of a file or directory.

    Args:
        path (str): Relative or absolute path.

    Returns:
        str: Absolute path.
    """
    return os.path.abspath(path)
# ==========================================================================================
# FUNCTION: is_file
# Check if a path is a file
# ==========================================================================================
def is_file(path):
    """
    Check if a path is a file.

    Args:
        path (str): Path to check.

    Returns:
        bool: True if the path is a file, False otherwise.
    """
    return os.path.isfile(path)
# ==========================================================================================
# FUNCTION: is_directory
# Check if a path is a directory
# ==========================================================================================
def is_directory(path):
    """
    Check if a path is a directory.

    Args:
        path (str): Path to check.

    Returns:
        bool: True if the path is a directory, False otherwise.
    """
    return os.path.isdir(path)
# ==========================================================================================
# FUNCTION: get_file_extension
# Get the file extension of a given file path
# ==========================================================================================
def get_file_extension(file_path):
    """
    Get the file extension of a given file path.

    Args:
        file_path (str): Path to the file.

    Returns:
        str: File extension (including the dot), or an empty string if no extension.
    """
    _, ext = os.path.splitext(file_path)
    return ext if ext else ""
# ==========================================================================================
# FUNCTION: get_file_name_without_extension
def get_file_name_without_extension(file_path):
    """
    Get the file name without its extension.

    Args:
        file_path (str): Path to the file.

    Returns:
        str: File name without extension.
    """
    return os.path.splitext(os.path.basename(file_path))[0]
# ==========================================================================================
# FUNCTION: get_directory_name
# Get the name of the directory containing the file
def get_directory_name(file_path):
    """
    Get the name of the directory containing the file.

    Args:
        file_path (str): Path to the file.

    Returns:
        str: Name of the directory containing the file.
    """
    return os.path.basename(os.path.dirname(file_path))
# ==========================================================================================
# FUNCTION: get_parent_directory
# Get the parent directory of a given path
def get_parent_directory(path):
    """
    Get the parent directory of a given path.

    Args:
        path (str): Path to the file or directory.

    Returns:
        str: Parent directory path.
    """
    return os.path.dirname(os.path.abspath(path))
# ==========================================================================================
# FUNCTION: get_relative_path
# Get the relative path from one directory to another
def get_relative_path(from_path, to_path):
    """
    Get the relative path from one directory to another.

    Args:
        from_path (str): Base path.
        to_path (str): Target path.

    Returns:
        str: Relative path from `from_path` to `to_path`.
    """
    return os.path.relpath(to_path, start=from_path)
# ==========================================================================================
# FUNCTION: copy_file
# Copy a file from source to destination
def copy_file(src, dst):
    """
    Copy a file from source to destination.

    Args:
        src (str): Source file path.
        dst (str): Destination file path.
    """
    import shutil
    if os.path.isfile(src):
        shutil.copy2(src, dst)
        print(f"[+] Copied file from {src} to {dst}")
    else:
        print(f"[!] Source file not found: {src}")
    
# ==========================================================================================
# FUNCTION: move_file
# Move a file from source to destination
def move_file(src, dst):
    """
    Move a file from source to destination.

    Args:
        src (str): Source file path.
        dst (str): Destination file path.
    """
    if os.path.isfile(src):
        shutil.move(src, dst)
        print(f"[+] Moved file from {src} to {dst}")
    else:
        print(f"[!] Source file not found: {src}")
# ==========================================================================================
# FUNCTION: get_file_creation_time
# Get the creation time of a file
def get_file_creation_time(file_path):
    """
    Get the creation time of a file.

    Args:
        file_path (str): Path to the file.

    Returns:
        float: Creation time as a timestamp, or None if the file does not exist.
    """
    if os.path.isfile(file_path):
        return os.path.getctime(file_path)
    else:
        print(f"[!] File not found: {file_path}")
        return None
# ==========================================================================================
# FUNCTION: get_file_modification_time
# Get the last modification time of a file
def get_file_modification_time(file_path):
    """
    Get the last modification time of a file.

    Args:
        file_path (str): Path to the file.

    Returns:
        float: Last modification time as a timestamp, or None if the file does not exist.
    """
    if os.path.isfile(file_path):
        return os.path.getmtime(file_path)
    else:
        print(f"[!] File not found: {file_path}")
        return None
# ==========================================================================================
# FUNCTION: get_file_access_time
# Get the last access time of a file
def get_file_access_time(file_path):
    """
    Get the last access time of a file.

    Args:
        file_path (str): Path to the file.

    Returns:
        float: Last access time as a timestamp, or None if the file does not exist.
    """
    if os.path.isfile(file_path):
        return os.path.getatime(file_path)
    else:
        print(f"[!] File not found: {file_path}")
        return None
# ==========================================================================================
# FUNCTION: get_file_hash
# Get the hash of a file using SHA-256
def get_file_hash(file_path):
    """
    Get the SHA-256 hash of a file.

    Args:
        file_path (str): Path to the file.

    Returns:
        str: SHA-256 hash of the file, or None if the file does not exist.
    """
    import hashlib
    if os.path.isfile(file_path):
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    else:
        print(f"[!] File not found: {file_path}")
        return None
# ==========================================================================================
# FUNCTION: get_directory_size
# Get the total size of all files in a directory
def get_directory_size(directory):
    """
    Get the total size of all files in a directory.

    Args:
        directory (str): Path to the directory.

    Returns:
        int: Total size in bytes, or -1 if the directory does not exist.
    """
    if os.path.isdir(directory):
        total_size = 0
        for dirpath, _, filenames in os.walk(directory):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                total_size += os.path.getsize(filepath)
        return total_size
    else:
        print(f"[!] Directory not found: {directory}")
        return -1
# ==========================================================================================
# FUNCTION: get_file_permissions
# Get the permissions of a file
def get_file_permissions(file_path):
    """
    Get the permissions of a file.

    Args:
        file_path (str): Path to the file.

    Returns:
        str: File permissions in octal format, or None if the file does not exist.
    """
    if os.path.isfile(file_path):
        return oct(os.stat(file_path).st_mode)[-3:]
    else:
        print(f"[!] File not found: {file_path}")
        return None
    #   - 2 hidden layers with 64 neurons each
#   - 3 output classes (low, medium, high severity)
model = CVESeverityNet(input_dim=5)

# ==========================================================================================
# STEP 5: TRAIN THE MODEL
# ==========================================================================================
# Define loss function and optimizer
criterion = nn.CrossEntropyLoss()  # Standard for multi-class classification
optimizer = optim.Adam(model.parameters(), lr=0.001)  # Adam optimizer with learning
# ==========================================================================================
# FUNCTION: get_file_owner
# Get the owner of a file
def get_file_owner(file_path):
    """
    Get the owner of a file.

    Args:
        file_path (str): Path to the file.

    Returns:
        str: Owner of the file, or None if the file does not exist.
    """
    if os.path.isfile(file_path):
        import pwd
        return pwd.getpwuid(os.stat(file_path).st_uid).pw_name
    else:
        print(f"[!] File not found: {file_path}")
        return None
def predict_severity(cve_features, model=None, scaler=None):
    """
    Perform prediction using the trained model and normalized features.

    Args:
        cve_features (list or np.ndarray): CVE features to predict severity for.
        model (nn.Module): Trained PyTorch model (default: None, will load if not provided).
        scaler (StandardScaler): Pre-fitted scaler for normalization (default: None, will load if not provided).

    Returns:
        str: Predicted severity level as a string ("Low", "Medium", "High", "Critical").
    """
    if model is None:
        model = load_model()
    if scaler is None:
        scaler = load_scaler()

    # Normalize input features
    cve_features = scaler.transform([cve_features])
    cve_tensor = torch.tensor(cve_features, dtype=torch.float32)

    # Get raw logits from the model
    with torch.no_grad():
        logits = model(cve_tensor)

    # Convert logits to probabilities and get predicted class
    probabilities = F.softmax(logits, dim=1)
    predicted_class = torch.argmax(probabilities, dim=1).item()

    # Map class index to severity level
    severity_levels = ["Low", "Medium", "High", "Critical"]
    return severity_levels[predicted_class]

# ==========================================================================================
# FUNCTION: load_model
# Load the trained CVE severity prediction model

def load_model(model_path="data/model_weights/severity_net.pt"):
    """
    Load the trained CVE severity prediction model.

    Args:
        model_path (str): Path to the saved model weights file.

    Returns:
        CVESeverityNet: Loaded model instance.
    """
    if os.path.exists(model_path):
        model = CVESeverityNet(input_dim=5)  # Initialize with correct input dimension
        model.load_state_dict(torch.load(model_path))
        model.eval()  # Set to evaluation mode
        print(f"[+] Model loaded from {model_path}")
        return model
    else:
        raise FileNotFoundError(f"[!] Model file not found at {model_path}")
# ==========================================================================================
# FUNCTION: load_scaler
# Load the StandardScaler used during training

def load_scaler(scaler_path="data/model_weights/scaler_severity.pkl"):
    """
    Load the StandardScaler used to normalize training data.

    Args:
        scaler_path (str): Path to the saved scaler file.

    Returns:
        StandardScaler: Pre-fitted scaler instance.
    """
    if os.path.exists(scaler_path):
        return joblib.load(scaler_path)
    else:
        raise FileNotFoundError(f"[!] Scaler file not found at {scaler_path}")