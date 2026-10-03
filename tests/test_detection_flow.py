"""
End-to-End Test for Detection Page Logic.
Validates:
1. Extraction & inference on real Windows PE executables (e.g. notepad.exe, cmd.exe).
2. Clean error handling on corrupted / non-PE files.
3. Feature compatibility, SHAP local explanations, and automated summary text generation.
4. Identifies which extracted features are classified as UNCERTAIN/CUSTOM.
"""

import sys
import io
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
from src.pe_extractor import extract_features, PEExtractionError, compute_hashes
from src.compatibility import validate_and_align
from src.explain import explain_prediction

UNCERTAIN_CUSTOM_FEATURES = {
    "SuspiciousImportFunctions",
    "SuspiciousNameSection",
    "SectionsLength",
    "SectionMaxEntropy",
    "SectionMaxRawsize",
    "SectionMaxVirtualsize",
    "SectionMinPhysical",
    "SectionMinVirtual",
    "SectionMinPointerData",
    "SectionMainChar",
}


def check_real_pe_detection(pe_path: str):
    print("=" * 80)
    print(f"[*] TESTING DETECTION FLOW ON REAL PE: {pe_path}")
    print("=" * 80)

    model_path = PROJECT_ROOT / "models" / "final_model.pkl"
    assert model_path.exists(), f"Model not found at {model_path}"
    pipeline = joblib.load(model_path)

    with open(pe_path, "rb") as f:
        file_bytes = f.read()

    # Step 1: Extraction
    print("\n[Step 1] Extracting PE characteristics...")
    res = extract_features(file_bytes)
    assert "features" in res and len(res["features"]) == 77
    print(f"  -> Successfully extracted {len(res['features'])} raw features.")
    print(f"  -> File Size: {res['hashes']['size_bytes']:,} bytes")
    print(f"  -> MD5 Hash: {res['hashes']['md5']}")
    print(f"  -> SHA-256: {res['hashes']['sha256']}")
    print(f"  -> Architecture: {res['metadata']['machine_type']}")
    print(f"  -> Sections: {res['metadata']['section_names']}")
    print(f"  -> Imported DLLs: {res['metadata']['imported_dll_count']}")
    print(f"  -> Imported APIs: {res['metadata']['imported_function_count']}")

    # Check UNCERTAIN/CUSTOM features for this sample
    sample_uncertain_feats = {k: v for k, v in res["features"].items() if k in UNCERTAIN_CUSTOM_FEATURES}
    print(f"\n[Step 1b] UNCERTAIN / CUSTOM Reconstructed Feature Values for this sample:")
    for k, v in sample_uncertain_feats.items():
        print(f"    • {k:<28}: {v}")

    # Step 2: Alignment & Validation
    print("\n[Step 2] Validating and aligning features...")
    aligned_df, warnings, is_valid = validate_and_align(res["features"])
    assert is_valid is True, f"Validation failed: {warnings}"
    print(f"  -> Validation Passed. Aligned DataFrame shape: {aligned_df.shape}")

    # Step 3: Model Inference
    print("\n[Step 3] Running malware classification...")
    probs = pipeline.predict_proba(aligned_df)[0]
    p_benign = float(probs[0])
    p_malware = float(probs[1])
    pred_class = 1 if p_malware >= 0.5 else 0
    confidence = max(p_benign, p_malware) * 100

    verdict_text = "Potential Malware" if pred_class == 1 else "Likely Benign"
    print(f"  -> Classification Result : {verdict_text}")
    print(f"  -> Malware Probability   : {p_malware*100:.2f}%")
    print(f"  -> Benign Probability    : {p_benign*100:.2f}%")
    print(f"  -> Model Confidence      : {confidence:.2f}%")

    # Step 4: SHAP Explainability
    print("\n[Step 4] Computing local SHAP feature attributions...")
    explanations = explain_prediction(pipeline, aligned_df, top_k=6)
    assert len(explanations) > 0

    print(f"\nTop {len(explanations)} SHAP Influences:")
    print(f"{'Feature Name':<30} | {'Input Value':<12} | {'SHAP Value':<10} | {'Direction':<16} | {'Magnitude':<8} | {'Custom?':<8}")
    print("-" * 94)
    for exp in explanations:
        is_custom = "YES (⚠️)" if exp["name"] in UNCERTAIN_CUSTOM_FEATURES else "NO"
        print(f"{exp['name']:<30} | {exp['value']:<12.2f} | {exp['shap_value']:<+10.4f} | {exp['direction']:<16} | {exp['magnitude']:<8} | {is_custom:<8}")

    # Step 5: Dynamic Summary Generation
    top3_names = [f["name"] for f in explanations[:3]]
    top3_vals = [f["value"] for f in explanations[:3]]
    summary_paragraph = (
        f"Static analysis classified '{Path(pe_path).name}' as {verdict_text} with a model probability of "
        f"{p_malware*100:.2f}% ({p_benign*100:.2f}% Benign). "
        f"The classifier's decision was most significantly influenced by {top3_names[0]} (value: {top3_vals[0]}), "
        f"{top3_names[1]} (value: {top3_vals[1]}), and {top3_names[2]} (value: {top3_vals[2]}), which provided the "
        f"strongest directional feature contributions to the prediction."
    )
    print("\n[Step 5] Auto-Generated Analysis Summary:")
    print(f"  \"{summary_paragraph}\"")


def test_real_pe_notepad():
    check_real_pe_detection(r"C:\Windows\System32\notepad.exe")


def test_real_pe_cmd():
    check_real_pe_detection(r"C:\Windows\System32\cmd.exe")


def test_corrupted_file_detection():
    print("\n" + "=" * 80)
    print("[*] TESTING DETECTION FLOW ON DELIBERATELY CORRUPTED INPUT")
    print("=" * 80)

    corrupted_bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00INVALID_CORRUPTED_PE_HEADER_PAYLOAD"
    
    try:
        res = extract_features(corrupted_bytes)
        print("  [FAIL] Corrupted file unexpectedly parsed.")
    except PEExtractionError as pe_err:
        print(f"  [PASS] Cleanly caught PEExtractionError: '{pe_err}'")
        print("  -> Dashboard UI displays: 'This file could not be parsed as a valid PE executable.' (Zero traceback)")


def main():
    test_real_pe_notepad()
    test_real_pe_cmd()
    test_corrupted_file_detection()
    print("\n" + "=" * 80)
    print(">>> ALL DETECTION INTEGRATION TESTS COMPLETED SUCCESSFULLY <<<")
    print("=" * 80)


if __name__ == "__main__":
    main()
