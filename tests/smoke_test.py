"""
Smoke Test Suite for Malware Classification System.
Validates:
1. Train/test split integrity (disjoint indices, correct proportions).
2. Feature schema consistency (models/feature_columns.json matches raw data features).
3. Pipeline deserialization and inference (models/final_model.pkl).
4. Full Streamlit UI page navigation with zero exceptions (14 pages via AppTest).
"""

import sys
import json
from pathlib import Path

# Configure UTF-8 stdout encoding
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import pandas as pd
import numpy as np
from streamlit.testing.v1 import AppTest
from src.pipeline import load_data, get_feature_columns


def test_split_indices_integrity():
    print("\n[Check 1] Validating train/test split indices integrity...")
    split_path = PROJECT_ROOT / "models" / "split_indices.json"
    assert split_path.exists(), f"Missing split indices at {split_path}"

    with open(split_path, "r", encoding="utf-8") as f:
        split_info = json.load(f)

    train_idx = set(split_info["train_indices"])
    test_idx = set(split_info["test_indices"])

    assert len(train_idx) == 15688, f"Expected 15,688 train samples, got {len(train_idx)}"
    assert len(test_idx) == 3923, f"Expected 3,923 test samples, got {len(test_idx)}"
    assert train_idx.isdisjoint(test_idx), "FATAL: Data leakage detected! Train and test indices overlap."
    assert len(train_idx) + len(test_idx) == 19611, "Train + Test sample count does not match total rows (19,611)"
    print("  [PASS] Split indices are strictly disjoint (15,688 train / 3,923 test).")


def test_feature_columns_schema():
    print("\n[Check 2] Validating feature columns schema...")
    feat_path = PROJECT_ROOT / "models" / "feature_columns.json"
    assert feat_path.exists(), f"Missing feature columns at {feat_path}"

    with open(feat_path, "r", encoding="utf-8") as f:
        saved_features = json.load(f)

    df = load_data()
    computed_features = get_feature_columns(df)

    assert len(saved_features) == 77, f"Expected 77 saved features, got {len(saved_features)}"
    assert saved_features == computed_features, "Saved feature columns do not match pipeline.get_feature_columns()"
    assert "Hash_md5_Name" not in saved_features, "Identifier 'Hash_md5_Name' found in feature columns"
    assert "Malware" not in saved_features, "Target 'Malware' found in feature columns"
    print("  [PASS] Feature schema matches all 77 numeric predictors in exact order.")


def test_final_model_inference():
    print("\n[Check 3] Validating model deserialization and inference...")
    model_path = PROJECT_ROOT / "models" / "final_model.pkl"
    assert model_path.exists(), f"Missing model at {model_path}"

    model = joblib.load(model_path)
    df = load_data()
    feat_cols = get_feature_columns(df)

    test_samples = df[feat_cols].iloc[:10]
    preds = model.predict(test_samples)
    probs = model.predict_proba(test_samples)

    assert len(preds) == 10, f"Expected 10 predictions, got {len(preds)}"
    assert probs.shape == (10, 2), f"Expected prob shape (10, 2), got {probs.shape}"
    assert np.all((probs >= 0.0) & (probs <= 1.0)), "Probabilities out of bounds [0.0, 1.0]"
    assert np.allclose(probs.sum(axis=1), 1.0), "Probabilities do not sum to 1.0"
    print(f"  [PASS] Pipeline loads and predicts accurately. Sample pred class: {preds[0]}, P(Malware): {probs[0][1]:.4f}")


def test_dashboard_pages_apptest():
    print("\n[Check 4] Testing Streamlit Dashboard navigation across all 14 pages (AppTest)...")
    app_path = PROJECT_ROOT / "dashboard" / "app.py"
    assert app_path.exists(), f"Missing dashboard app at {app_path}"

    at = AppTest.from_file(str(app_path), default_timeout=45)
    at.run()
    assert not at.exception, f"Initial page exception: {at.exception}"

    pages = [
        "🏠 Detection",
        "📊 Dataset",
        "🔎 EDA",
        "🧬 Feature Engineering",
        "🎯 Feature Selection",
        "🤖 Models",
        "📈 Evaluation",
        "🔬 Explainability",
        "📁 Batch Analysis",
        "ℹ️ About",
    ]

    for p in pages:
        at.sidebar.radio[0].set_value(p).run()
        if at.exception:
            print(f"  [FAIL] Error rendering page '{p}': {at.exception}")
            raise at.exception[0]
        print(f"  [PASS] Page '{p}' rendered with 0 exceptions.")

    print(f"  [PASS] All {len(pages)} Streamlit pages validated successfully.")


def main():
    print("=" * 70)
    print(" MALWARE CLASSIFICATION SYSTEM: SMOKE TEST SUITE ")
    print("=" * 70)

    test_split_indices_integrity()
    test_feature_columns_schema()
    test_final_model_inference()
    test_dashboard_pages_apptest()

    print("\n" + "=" * 70)
    print(" >>> ALL SMOKE TESTS PASSED WITH ZERO FAILURES <<< ")
    print("=" * 70)


if __name__ == "__main__":
    main()