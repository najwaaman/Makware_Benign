"""
Verification Script for Malware Classification Dataset & Pipeline Utilities.
"""

import sys
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.pipeline import (
    load_data,
    dataset_summary,
    get_feature_columns,
    FeatureEngineer,
    CorrelationFilter,
)


def main():
    print("=" * 70)
    print(" MALWARE DATASET INTEGRITY & PIPELINE CHECK ")
    print("=" * 70)

    # 1. Load Data
    print("\n[1] Loading dataset via load_data()...")
    df = load_data()
    print(f"    Dataset loaded successfully from: data/Malware-Benign.csv")

    # 2. Dataset Summary
    print("\n[2] Computing dataset summary...")
    summary = dataset_summary(df)
    
    print("\n" + "-" * 40 + " DATASET METRICS " + "-" * 40)
    print(f"  * Total Rows                       : {summary['total_rows']:,}")
    print(f"  * Total Columns                    : {summary['total_columns']:,}")
    print(f"  * Malware Samples (Class 1)        : {summary['malware_count']:,} ({summary['malware_percentage']}%)")
    print(f"  * Benign Samples (Class 0)         : {summary['benign_count']:,} ({summary['benign_percentage']}%)")
    print(f"  * Missing Values (Total Cells)     : {summary['missing_values']:,}")
    print(f"  * Full Duplicate Rows (All Cols)   : {summary['duplicate_full_rows']:,}")
    print(f"  * Numeric Feature Columns Count    : {summary['numeric_features_count']:,}")
    print(f"  * Feature Duplicates (Redundant)   : {summary['duplicate_feature_rows']:,}")
    print(f"  * Feature Duplicates (Total Rows)  : {summary['duplicate_feature_total_occurrences']:,}")
    print(f"  * Has Conflicting Labels?          : {summary['has_conflicting_labels']}")
    print(f"  * Conflicting Feature Groups       : {summary['conflicting_label_groups']:,}")
    print(f"  * Rows with Conflicting Labels     : {summary['conflicting_label_rows']:,}")
    print("-" * 97)

    # 3. Numeric Feature Columns
    print("\n[3] Validating Feature Columns...")
    feat_cols = get_feature_columns(df)
    print(f"    Identified {len(feat_cols)} numeric feature columns (excluded 'Hash_md5_Name' and 'Malware').")

    # 4. Feature Engineering Pipeline Test
    print("\n[4] Testing FeatureEngineer Transformer...")
    fe = FeatureEngineer()
    X = df[feat_cols].copy()
    fe.fit(X)
    X_eng = fe.transform(X)
    new_cols = [c for c in X_eng.columns if c not in feat_cols]
    print(f"    Engineered {len(new_cols)} new domain features: {new_cols}")
    print(f"    Transformed shape: {X_eng.shape}")

    # 5. Correlation Filter Pipeline Test
    print("\n[5] Testing CorrelationFilter Transformer (threshold=0.95)...")
    cf = CorrelationFilter(threshold=0.95)
    cf.fit(X_eng)
    X_filtered = cf.transform(X_eng)
    print(f"    Dropped collinear features ({len(cf.dropped_features_)}): {cf.dropped_features_}")
    print(f"    Remaining features count: {len(cf.retained_features_)}")
    print(f"    Final transformed shape: {X_filtered.shape}")

    print("\n" + "=" * 70)
    print(" ALL CHECKS COMPLETED SUCCESSFULLY ")
    print("=" * 70)


if __name__ == "__main__":
    main()
