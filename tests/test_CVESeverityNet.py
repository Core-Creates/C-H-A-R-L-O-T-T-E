# ruff: noqa: E402
# Reason: this script adjusts sys.path before importing project modules.
import os
import sys
import torch
import unittest


# Add CHARLOTTE root directory to sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Now you can import from models/cve_severity_predictor.py
from models.cve_severity_predictor import CVESeverityNet, predict_severity


class TestCVESeverityPredictor(unittest.TestCase):
    def test_model_forward_pass(self):
        """Test forward pass with dummy input"""
        model = CVESeverityNet()
        dummy_input = torch.rand(1, 5)  # Batch size 1, 5 input features
        output = model(dummy_input)
        self.assertEqual(
            output.shape, (1, 4)
        )  # Expect 4 logits (Low, Medium, High, Critical)

    def test_model_file_exists(self):
        """Check if the model weights file exists"""
        model_path = "data/model_weights/severity_net.pt"
        self.assertTrue(os.path.exists(model_path), f"Missing model file: {model_path}")

    def test_scaler_file_exists(self):
        """Check if the scaler file exists"""
        scaler_path = "data/model_weights/scaler_severity.pkl"
        self.assertTrue(
            os.path.exists(scaler_path), f"Missing scaler file: {scaler_path}"
        )

    def test_predict_severity_output(self):
        """Test if prediction returns a valid severity class"""
        sample_input = [7.5, 6.4, 2.8, 1, 15]  # Example feature vector
        prediction = predict_severity(sample_input)
        self.assertIn(
            prediction,
            ["Low", "Medium", "High", "Critical"],
            "Invalid severity prediction",
        )

    def test_predict_consistency(self):
        """Test that prediction runs twice and produces consistent output for same input"""
        input_sample = [6.1, 5.5, 3.0, 0, 9]
        pred1 = predict_severity(input_sample)
        pred2 = predict_severity(input_sample)
        self.assertEqual(pred1, pred2, "Predictions should be consistent across runs")


if __name__ == "__main__":
    unittest.main()
    # scaler = load_scaler()
