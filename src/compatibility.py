"""
Feature Compatibility and Alignment Module.
Ensures extracted PE feature dictionaries strictly match the trained pipeline schema.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
FEATURE_COLUMNS_PATH = PROJECT_ROOT / "models" / "feature_columns.json"


def load_expected_feature_columns() -> List[str]:
    """Load the exact ordered list of 77 feature names expected by the model pipeline."""
    if not FEATURE_COLUMNS_PATH.exists():
        raise FileNotFoundError(f"Feature columns schema not found at {FEATURE_COLUMNS_PATH}")
    with open(FEATURE_COLUMNS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_and_align(
    extracted_features: Dict[str, Any]
) -> Tuple[Optional[pd.DataFrame], List[str], bool]:
    """
    Validates extracted features against the expected pipeline schema and aligns them
    into a single-row DataFrame with the exact column order expected by the model.

    Args:
        extracted_features: Dict mapping feature names to extracted values.

    Returns:
        Tuple containing:
            - aligned_dataframe (pd.DataFrame or None): 1-row DataFrame strictly ordered if valid, else None.
            - warnings (List[str]): List of validation error or informational warning strings.
            - is_valid (bool): True if all required features exist and are valid numeric values.
    """
    expected_columns = load_expected_feature_columns()
    warnings: List[str] = []
    missing_columns: List[str] = []
    non_numeric_columns: List[str] = []
    row_values: List[float] = []

    if not isinstance(extracted_features, dict):
        return None, ["Input extracted_features must be a dictionary."], False

    extracted_keys = set(extracted_features.keys())
    expected_keys = set(expected_columns)

    # 1. Identify extra columns (non-fatal warning)
    extra_keys = extracted_keys - expected_keys
    if extra_keys:
        warnings.append(
            f"Found {len(extra_keys)} non-standard extra keys in feature input. "
            f"These will be ignored: {sorted(list(extra_keys))[:5]}..."
        )

    # 2. Check each expected feature in exact order
    for col in expected_columns:
        if col not in extracted_features:
            missing_columns.append(col)
            continue

        raw_val = extracted_features[col]
        
        # Check numeric type or convertible to float
        if raw_val is None:
            missing_columns.append(f"{col} (value is None)")
            continue

        try:
            val_float = float(raw_val)
            if np.isnan(val_float) or np.isinf(val_float):
                non_numeric_columns.append(f"{col} (NaN/Inf value: {raw_val})")
            else:
                row_values.append(val_float)
        except (ValueError, TypeError):
            non_numeric_columns.append(f"{col} (cannot convert '{raw_val}' of type {type(raw_val).__name__} to float)")

    # 3. Determine validity
    if missing_columns:
        warnings.insert(
            0,
            f"Missing {len(missing_columns)} required feature(s): {missing_columns}"
        )
    if non_numeric_columns:
        warnings.insert(
            0,
            f"Non-numeric / invalid value detected in {len(non_numeric_columns)} feature(s): {non_numeric_columns}"
        )

    is_valid = (len(missing_columns) == 0) and (len(non_numeric_columns) == 0)

    if not is_valid:
        return None, warnings, False

    # 4. Build single-row DataFrame in exact expected column order
    aligned_df = pd.DataFrame([row_values], columns=expected_columns)
    return aligned_df, warnings, True