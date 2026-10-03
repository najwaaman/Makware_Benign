"""
Unit and Integration Tests for Compatibility Validation and SHAP Explainability.
Tests validate_and_align() and explain_prediction() on actual test-set data and trained pipeline.
"""

import json
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Fix console encoding on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

import joblib
import pandas as pd
from src.compatibility import validate_and_align, load_expected_feature_columns
from src.explain import explain_prediction


def test_compatibility_validation():
    print("\n" + "=" * 60)
    print("[TEST 1] Testing src/compatibility.py: validate_and_align()")
    print("=" * 60)

    expected_cols = load_expected_feature_columns()
    print(f"Loaded {len(expected_cols)} expected feature columns.")
    assert len(expected_cols) == 77, f"Expected 77 features, found {len(expected_cols)}"

    # Case A: Valid full dictionary
    dummy_sample = {col: 100.0 for col in expected_cols}
    dummy_sample["extra_unwanted_column"] = 999.0  # Extra column to test warning
    df_aligned, warnings, is_valid = validate_and_align(dummy_sample)

    assert is_valid is True, f"Expected is_valid=True for valid input, got {is_valid}. Warnings: {warnings}"
    assert df_aligned is not None, "aligned_df should not be None"
    assert df_aligned.shape == (1, 77), f"Expected shape (1, 77), got {df_aligned.shape}"
    assert list(df_aligned.columns) == expected_cols, "Columns are not in the exact expected order"
    print(f"  [PASS] Valid input test passed. Extra columns handled gracefully with warning: {warnings}")

    # Case B: Missing required features
    incomplete_sample = {col: 1.0 for col in expected_cols[:50]}  # missing 27 columns
    df_aligned_bad, warnings_bad, is_valid_bad = validate_and_align(incomplete_sample)

    assert is_valid_bad is False, "Expected is_valid=False for incomplete input"
    assert df_aligned_bad is None, "aligned_df should be None when invalid"
    assert any("Missing 27 required feature" in w for w in warnings_bad), f"Warning should mention missing features: {warnings_bad}"
    print("  [PASS] Missing columns correctly rejected with informative warnings.")

    # Case C: Invalid non-numeric values
    corrupted_sample = {col: 1.0 for col in expected_cols}
    corrupted_sample["TimeDateStamp"] = "INVALID_STRING"
    df_aligned_c, warnings_c, is_valid_c = validate_and_align(corrupted_sample)

    assert is_valid_c is False, "Expected is_valid=False for non-numeric input"
    assert df_aligned_c is None
    assert any("Non-numeric / invalid value" in w for w in warnings_c)
    print("  [PASS] Non-numeric input correctly rejected with validation warning.")


def test_explain_predictions():
    print("\n" + "=" * 60)
    print("[TEST 2] Testing src/explain.py: explain_prediction() with SHAP")
    print("=" * 60)

    model_path = PROJECT_ROOT / "models" / "final_model.pkl"
    data_path = PROJECT_ROOT / "data" / "Malware-Benign.csv"
    split_path = PROJECT_ROOT / "models" / "split_indices.json"

    assert model_path.exists(), f"Model artifact not found at {model_path}"
    assert data_path.exists(), f"Dataset not found at {data_path}"
    assert split_path.exists(), f"Split indices not found at {split_path}"

    pipeline = joblib.load(model_path)
    df = pd.read_csv(data_path)
    with open(split_path, "r", encoding="utf-8") as f:
        split_data = json.load(f)
    test_indices = split_data.get("test_indices", split_data) if isinstance(split_data, dict) else split_data

    test_df = df.iloc[test_indices].copy()
    expected_cols = load_expected_feature_columns()

    # Find one Benign (Malware == 0) and one Malware (Malware == 1) sample from test set
    benign_rows = test_df[test_df["Malware"] == 0]
    malware_rows = test_df[test_df["Malware"] == 1]

    assert len(benign_rows) > 0, "No benign samples found in test split"
    assert len(malware_rows) > 0, "No malware samples found in test split"

    benign_sample = benign_rows.iloc[0][expected_cols].to_dict()
    malware_sample = malware_rows.iloc[0][expected_cols].to_dict()

    # Explain Benign Sample
    print(f"\n--- Explaining Test Sample 1: BENIGN (True Label = 0) ---")
    df_benign, _, _ = validate_and_align(benign_sample)
    pred_prob_b = pipeline.predict_proba(df_benign)[0]
    print(f"Model Predicted Probabilities: Benign={pred_prob_b[0]:.4f}, Malware={pred_prob_b[1]:.4f}")

    benign_explanations = explain_prediction(pipeline, df_benign, top_k=8)
    assert len(benign_explanations) > 0, "Explanations list is empty"
    assert len(benign_explanations) <= 8, f"Expected <= 8 items, got {len(benign_explanations)}"

    print(f"\nTop {len(benign_explanations)} SHAP Influences for Benign Sample:")
    print(f"{'Feature Name':<30} | {'Input Value':<12} | {'SHAP Value':<10} | {'Direction':<16} | {'Magnitude':<8}")
    print("-" * 84)
    for exp in benign_explanations:
        assert all(k in exp for k in ["name", "value", "shap_value", "direction", "magnitude", "impact_description"])
        assert exp["direction"] in ["Toward Malware", "Toward Benign", "Neutral"]
        assert exp["magnitude"] in ["High", "Medium", "Low"]
        print(f"{exp['name']:<30} | {exp['value']:<12.2f} | {exp['shap_value']:<+10.4f} | {exp['direction']:<16} | {exp['magnitude']:<8}")

    # Explain Malware Sample
    print(f"\n--- Explaining Test Sample 2: MALWARE (True Label = 1) ---")
    df_malware, _, _ = validate_and_align(malware_sample)
    pred_prob_m = pipeline.predict_proba(df_malware)[0]
    print(f"Model Predicted Probabilities: Benign={pred_prob_m[0]:.4f}, Malware={pred_prob_m[1]:.4f}")

    malware_explanations = explain_prediction(pipeline, df_malware, top_k=8)
    assert len(malware_explanations) > 0, "Explanations list is empty"

    print(f"\nTop {len(malware_explanations)} SHAP Influences for Malware Sample:")
    print(f"{'Feature Name':<30} | {'Input Value':<12} | {'SHAP Value':<10} | {'Direction':<16} | {'Magnitude':<8}")
    print("-" * 84)
    for exp in malware_explanations:
        print(f"{exp['name']:<30} | {exp['value']:<12.2f} | {exp['shap_value']:<+10.4f} | {exp['direction']:<16} | {exp['magnitude']:<8}")

    print("\n" + "=" * 60)
    print("ALL COMPATIBILITY AND EXPLAINABILITY TESTS PASSED!")
    print("=" * 60)


if __name__ == "__main__":
    test_compatibility_validation()
    test_explain_predictions()
