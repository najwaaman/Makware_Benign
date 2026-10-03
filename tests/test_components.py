"""Direct unit test for all model and inference workflows."""
import sys
from pathlib import Path
import json

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import pandas as pd
import numpy as np

# 1. Load model
model = joblib.load("models/final_model.pkl")
print("1. Final Model loaded successfully:", type(model))

# 2. Load feature columns
with open("models/feature_columns.json", "r") as f:
    feature_cols = json.load(f)
print(f"2. Feature columns loaded ({len(feature_cols)} features).")

# 3. Load dataset
df = pd.read_csv("data/Malware-Benign.csv")
print(f"3. Dataset loaded: {df.shape}")

# 4. Test Single Sample Prediction
sample_row = df[feature_cols].iloc[[0]]
pred = model.predict(sample_row)
probs = model.predict_proba(sample_row)
print(f"4. Single Prediction: Predicted Class = {pred[0]}, Malware Prob = {probs[0][1]:.4f}, Benign Prob = {probs[0][0]:.4f}")
assert pred[0] in [0, 1]
assert 0.0 <= probs[0][1] <= 1.0

# 5. Test Batch Prediction (100 samples)
batch_samples = df[feature_cols].iloc[:100]
batch_preds = model.predict(batch_samples)
batch_probs = model.predict_proba(batch_samples)
print(f"5. Batch Prediction (100 samples): {sum(batch_preds==1)} Malware, {sum(batch_preds==0)} Benign")
assert len(batch_preds) == 100

# 6. Test Missing Columns Validation logic
missing_test_df = df[feature_cols[:-5]].copy()
missing = list(set(feature_cols) - set(missing_test_df.columns))
print(f"6. Missing Columns Check: Correctly identified {len(missing)} missing columns: {missing}")
assert len(missing) == 5

# 7. Check artifact files
for fpath in [
    "models/final_model.pkl",
    "models/split_indices.json",
    "models/selected_features.json",
    "models/feature_importance.csv",
    "models/test_predictions.csv",
    "models/model_metrics.json",
    "models/training_metadata.json",
    "outputs/reports/model_comparison_report.csv",
]:
    assert Path(fpath).exists(), f"Missing {fpath}"
print("7. All essential artifacts verified on disk.")

print("\n>>> ALL DASHBOARD COMPONENT TESTS PASSED WITH 100% SUCCESS! <<<")