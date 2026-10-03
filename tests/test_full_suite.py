"""
Comprehensive End-to-End Verification Test Suite.
Validates all subsystems:
1. Dataset ingestion and schema validation.
2. Model pipeline loading and deserialization.
3. Live PE extraction on valid Windows system binaries.
4. Robust failure handling on corrupt and non-PE data.
5. Benign and Malware test sample inferences with probability calculation.
6. SHAP TreeExplainer feature attributions and magnitude/direction categorization.
7. Batch CSV prediction pipeline and output formatting.
8. Artifact and export file availability for all download endpoints.
"""

import json
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Console encoding on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

import joblib
import numpy as np
import pandas as pd
from src.pipeline import load_data, dataset_summary, get_feature_columns
from src.pe_extractor import extract_features, PEExtractionError, compute_hashes
from src.compatibility import validate_and_align
from src.explain import explain_prediction


def run_full_system_checks():
    print("=" * 80)
    print(" MALWARE SENTINEL: FULL SYSTEM INTEGRATION VERIFICATION ")
    print("=" * 80)

    # 1. Dataset Loading
    print("\n[1/8] Checking Dataset Loading & Statistics...")
    df = load_data()
    assert len(df) == 19611, f"Expected 19,611 rows, got {len(df)}"
    summary = dataset_summary(df)
    assert summary["missing_values"] == 0
    print(f"  [PASS] Loaded {len(df):,} rows with {summary['numeric_features_count']} numeric predictors.")

    # 2. Model Loading & Verification
    print("\n[2/8] Checking Model Pipeline Loading & Metadata...")
    model_path = PROJECT_ROOT / "models" / "final_model.pkl"
    meta_path = PROJECT_ROOT / "models" / "training_metadata.json"
    metrics_path = PROJECT_ROOT / "models" / "model_metrics.json"

    assert model_path.exists(), "final_model.pkl missing"
    assert meta_path.exists(), "training_metadata.json missing"
    assert metrics_path.exists(), "model_metrics.json missing"

    pipeline = joblib.load(model_path)
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
    with open(metrics_path, "r", encoding="utf-8") as f:
        metrics = json.load(f)

    print(f"  [PASS] Pipeline loaded. Model: {meta.get('selected_model')} | Selected Features: {meta.get('final_selected_features_count')}")
    test_metrics = metrics["test_set_evaluation"][meta["selected_model"]]
    print(f"  [METRICS] Test Acc: {test_metrics['accuracy']:.4f} | Prec: {test_metrics['precision']:.4f} | Rec: {test_metrics['recall']:.4f} | F1: {test_metrics['f1_score']:.4f} | ROC-AUC: {test_metrics['roc_auc']:.4f}")

    # 3. PE Extraction on Valid Executable
    print("\n[3/8] Checking Live PE Extraction on notepad.exe...")
    with open(r"C:\Windows\System32\notepad.exe", "rb") as f:
        pe_bytes = f.read()
    res = extract_features(pe_bytes)
    assert len(res["features"]) == 77
    assert res["metadata"]["is_pe"] is True
    print(f"  [PASS] Extracted {len(res['features'])} features, {res['metadata']['number_of_sections']} sections, {res['metadata']['imported_dll_count']} DLLs.")

    # 4. Corrupt File Handling
    print("\n[4/8] Checking Error Handling on Corrupted Binary...")
    corrupt_data = b"NOT_A_PE_CORRUPT_HEADER_STREAM_DATA"
    try:
        extract_features(corrupt_data)
        assert False, "Should have raised PEExtractionError"
    except PEExtractionError as e:
        print(f"  [PASS] Cleanly rejected corrupted binary: '{e}'")

    # 5. Benign & Malware Inferences
    print("\n[5/8] Checking Inferences on Test Samples (Benign & Malware)...")
    feat_cols = get_feature_columns(df)
    with open(PROJECT_ROOT / "models" / "split_indices.json", "r", encoding="utf-8") as f:
        split_data = json.load(f)
    test_idx = split_data["test_indices"] if isinstance(split_data, dict) else split_data
    test_df = df.iloc[test_idx]

    benign_sample = test_df[test_df["Malware"] == 0].iloc[0][feat_cols].to_dict()
    malware_sample = test_df[test_df["Malware"] == 1].iloc[0][feat_cols].to_dict()

    df_b, _, _ = validate_and_align(benign_sample)
    df_m, _, _ = validate_and_align(malware_sample)

    prob_b = pipeline.predict_proba(df_b)[0]
    prob_m = pipeline.predict_proba(df_m)[0]

    assert prob_b[0] > prob_b[1], "Benign sample should have higher benign probability"
    assert prob_m[1] > prob_m[0], "Malware sample should have higher malware probability"
    print(f"  [PASS] Benign Sample -> Prob(Benign): {prob_b[0]*100:.2f}%, Prob(Malware): {prob_b[1]*100:.2f}% (Class {np.argmax(prob_b)})")
    print(f"  [PASS] Malware Sample -> Prob(Malware): {prob_m[1]*100:.2f}%, Prob(Benign): {prob_m[0]*100:.2f}% (Class {np.argmax(prob_m)})")

    # 6. SHAP TreeExplainer Attributions
    print("\n[6/8] Checking SHAP TreeExplainer Attributions...")
    exps_b = explain_prediction(pipeline, df_b, top_k=6)
    exps_m = explain_prediction(pipeline, df_m, top_k=6)
    assert len(exps_b) == 6
    assert len(exps_m) == 6
    print(f"  [PASS] Benign top SHAP contributor: {exps_b[0]['name']} ({exps_b[0]['direction']}, SHAP={exps_b[0]['shap_value']:+.4f})")
    print(f"  [PASS] Malware top SHAP contributor: {exps_m[0]['name']} ({exps_m[0]['direction']}, SHAP={exps_m[0]['shap_value']:+.4f})")

    # 7. Batch CSV Processing Pipeline
    print("\n[7/8] Checking Batch CSV Feature Prediction...")
    batch_input = test_df.head(25)[feat_cols].copy()
    batch_probs = pipeline.predict_proba(batch_input)
    assert len(batch_probs) == 25
    batch_preds = (batch_probs[:, 1] >= 0.5).astype(int)
    print(f"  [PASS] Batch of 25 records classified successfully. Malware: {np.sum(batch_preds == 1)}, Benign: {np.sum(batch_preds == 0)}")

    # 8. Artifact and Download File Availability
    print("\n[8/8] Checking Artifact & Download Report Availability...")
    required_files = [
        PROJECT_ROOT / "outputs" / "reports" / "model_comparison_report.csv",
        PROJECT_ROOT / "outputs" / "reports" / "classification_reports.json",
        PROJECT_ROOT / "models" / "selected_features.json",
        PROJECT_ROOT / "models" / "feature_importance.csv",
        PROJECT_ROOT / "outputs" / "confusion_matrix" / "confusion_matrices_all.png",
        PROJECT_ROOT / "outputs" / "roc_curves" / "roc_curves_all.png",
        PROJECT_ROOT / "outputs" / "roc_curves" / "pr_curves_all.png",
        PROJECT_ROOT / "outputs" / "feature_importance" / "top_features.png",
    ]
    for rf in required_files:
        assert rf.exists(), f"Required download artifact missing: {rf}"
        print(f"  [PASS] Found artifact: {rf.name} ({rf.stat().st_size:,} bytes)")

    print("\n" + "=" * 80)
    print(" >>> ALL 8 SUBSYSTEM INTEGRATION CHECKS PASSED WITH ZERO ERRORS! <<< ")
    print("=" * 80)


if __name__ == "__main__":
    run_full_system_checks()
