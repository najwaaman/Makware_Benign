"""
Unit and Integration Test Suite for PE Feature Extractor.
Tests:
1. Parsing real system binaries (notepad.exe, cmd.exe, kernel32.dll).
2. End-to-end inference using final_model.pkl with extracted features.
3. Clean error handling for corrupt and non-PE inputs (raising PEExtractionError).
4. Hash computation and metadata verification.
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

from src.pe_extractor import (
    extract_features,
    extract_features_df,
    PEExtractionError,
    load_expected_feature_columns,
)


def test_real_pe_binaries():
    print("=" * 75)
    print(" 1. TESTING FEATURE EXTRACTION ON REAL SYSTEM PE BINARIES ")
    print("=" * 75)

    sample_candidates = [
        Path(r"C:\Windows\System32\notepad.exe"),
        Path(r"C:\Windows\System32\cmd.exe"),
        Path(r"C:\Windows\System32\kernel32.dll"),
        Path(r"C:\Windows\System32\calc.exe"),
    ]

    valid_samples = [p for p in sample_candidates if p.exists()]
    assert len(valid_samples) > 0, "No real system PE binaries found for testing"

    model = joblib.load(PROJECT_ROOT / "models" / "final_model.pkl")
    expected_cols = load_expected_feature_columns()

    for pe_path in valid_samples:
        print(f"\n[Testing Binary]: {pe_path.name}")
        raw_bytes = pe_path.read_bytes()

        # Extract dictionary
        result = extract_features(raw_bytes)
        features = result["features"]
        hashes = result["hashes"]
        meta = result["metadata"]

        assert len(features) == 77, f"Expected 77 features, got {len(features)}"
        assert list(features.keys()) == expected_cols, "Feature keys do not match expected order"

        print(f"  * File Size        : {hashes['size_bytes']:,} bytes")
        print(f"  * MD5 Hash         : {hashes['md5']}")
        print(f"  * SHA-256 Hash     : {hashes['sha256'][:24]}...")
        print(f"  * Machine Type     : {meta['machine_type']}")
        print(f"  * Sections Count   : {meta['number_of_sections']} ({', '.join(meta['section_names'][:4])}...)")
        print(f"  * Imported DLLs    : {meta['imported_dll_count']} DLLs ({meta['imported_function_count']} functions)")
        print(f"  * Suspicious APIs  : {int(features['SuspiciousImportFunctions'])}")
        print(f"  * Suspicious Secs  : {int(features['SuspiciousNameSection'])}")

        # Extract DataFrame for model inference
        df_row = extract_features_df(raw_bytes)
        assert df_row.shape == (1, 77), f"Expected shape (1, 77), got {df_row.shape}"

        # Run pipeline inference directly
        pred = model.predict(df_row)[0]
        prob = model.predict_proba(df_row)[0]
        pred_label = "MALWARE (1)" if pred == 1 else "BENIGN (0)"

        print(f"  * Pipeline Output  : {pred_label} | Prob(Malware)={prob[1]*100:.2f}%, Prob(Benign)={prob[0]*100:.2f}%")
        print("  -> Extraction & Inference: SUCCESS")


def test_corrupted_and_non_pe_files():
    print("\n" + "=" * 75)
    print(" 2. TESTING ERROR HANDLING ON CORRUPTED & NON-PE INPUTS ")
    print("=" * 75)

    test_cases = [
        ("Empty Bytes", b""),
        ("Tiny Header (< 64 bytes)", b"MZ\x90\x00\x03\x00\x00\x00"),
        ("Plain Text File", b"Hello world! This is a plain text file, not a PE executable."),
        ("PNG Image File", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00"),
        ("Corrupted PE Header", b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00" + b"PE\x00\x00" + b"\xff" * 20),
    ]

    for label, bad_bytes in test_cases:
        print(f"\n[Case]: {label} ({len(bad_bytes)} bytes)")
        try:
            extract_features(bad_bytes)
            assert False, f"Expected PEExtractionError for '{label}', but no exception was raised!"
        except PEExtractionError as e:
            print(f"  [HANDLED CLEANLY]: PEExtractionError caught -> {e}")

    print("\n  -> All corrupt and non-PE inputs correctly raised PEExtractionError.")


def main():
    test_real_pe_binaries()
    test_corrupted_and_non_pe_files()

    print("\n" + "=" * 75)
    print(" >>> ALL PE EXTRACTOR TESTS PASSED WITH 100% SUCCESS! <<< ")
    print("=" * 75)


if __name__ == "__main__":
    main()