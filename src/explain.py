"""
Model Explainability and Local Inference Interpretation Module.
Computes sample-level SHAP contributions for PE feature predictions.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

import numpy as np
import pandas as pd
import shap
from sklearn.pipeline import Pipeline
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import (
    RandomForestClassifier,
    HistGradientBoostingClassifier,
    GradientBoostingClassifier,
)
from sklearn.linear_model import LogisticRegression

PROJECT_ROOT = Path(__file__).resolve().parent.parent
METADATA_PATH = PROJECT_ROOT / "models" / "training_metadata.json"
IMPORTANCE_PATH = PROJECT_ROOT / "models" / "feature_importance.csv"
FEATURE_COLUMNS_PATH = PROJECT_ROOT / "models" / "feature_columns.json"


def load_feature_columns() -> List[str]:
    """Load ordered feature columns."""
    if FEATURE_COLUMNS_PATH.exists():
        with open(FEATURE_COLUMNS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def explain_prediction(
    pipeline: Pipeline,
    input_row: Union[pd.DataFrame, pd.Series, Dict[str, Any]],
    top_k: int = 8,
) -> List[Dict[str, Any]]:
    """
    Computes local feature attribution (SHAP values) for a single PE binary prediction.

    Args:
        pipeline: Trained scikit-learn Pipeline (or loaded final_model.pkl).
        input_row: 1-row DataFrame, Series, or dict containing the 77 raw PE features.
        top_k: Number of top influential features to return (default 8, typically 5-8).

    Returns:
        List[Dict[str, Any]] containing top_k features sorted by |SHAP value|:
            - 'name': Feature name (str)
            - 'value': Input feature value (float)
            - 'shap_value': SHAP attribution score (float)
            - 'direction': 'Toward Malware' or 'Toward Benign' (str)
            - 'magnitude': 'High', 'Medium', or 'Low' (str)
            - 'impact_description': Human-readable summary (str)
    """
    feature_cols = load_feature_columns()

    # 1. Standardize input_row into a 1-row DataFrame
    if isinstance(input_row, dict):
        if feature_cols:
            row_vals = [input_row.get(c, 0.0) for c in feature_cols]
            input_df = pd.DataFrame([row_vals], columns=feature_cols)
        else:
            input_df = pd.DataFrame([input_row])
    elif isinstance(input_row, pd.Series):
        input_df = pd.DataFrame([input_row.values], columns=input_row.index)
    elif isinstance(input_row, pd.DataFrame):
        input_df = input_row.iloc[[0]].copy()
    else:
        raise ValueError(f"Unsupported input_row type: {type(input_row)}")

    # 2. Transform input through the pipeline steps preceding the classifier
    X_transformed = input_df.copy()
    for name, step in pipeline.steps[:-1]:
        X_transformed = step.transform(X_transformed)

    classifier = pipeline.named_steps["classifier"]
    transformed_feature_names = list(X_transformed.columns)

    shap_values_arr: Optional[np.ndarray] = None
    explanation_source: str = "SHAP TreeExplainer"

    # 3. Detect Classifier Type and Compute Attribution
    try:
        # A. Tree-based Models (Random Forest, Decision Tree, HistGradientBoosting)
        if isinstance(
            classifier,
            (
                HistGradientBoostingClassifier,
                RandomForestClassifier,
                DecisionTreeClassifier,
                GradientBoostingClassifier,
            ),
        ) or hasattr(classifier, "tree_") or hasattr(classifier, "estimators_"):
            explainer = shap.TreeExplainer(classifier)
            raw_shap = explainer.shap_values(X_transformed)

            # Handle different output structures of TreeExplainer across sklearn versions
            if isinstance(raw_shap, list):
                # Binary classification list: [class_0_shap, class_1_shap]
                shap_values_arr = np.array(raw_shap[1][0])
            elif isinstance(raw_shap, np.ndarray):
                if raw_shap.ndim == 3:
                    # Shape (1, n_features, n_classes) -> extract class 1
                    shap_values_arr = raw_shap[0, :, 1]
                elif raw_shap.ndim == 2:
                    # Shape (1, n_features) -> log-odds for binary
                    shap_values_arr = raw_shap[0]
                else:
                    shap_values_arr = raw_shap.flatten()

        # B. Linear Models (Logistic Regression)
        elif isinstance(classifier, LogisticRegression) or hasattr(classifier, "coef_"):
            if hasattr(classifier, "coef_"):
                # Approximate attribution: scaled_feature_value * coefficient
                coefs = classifier.coef_[0]
                X_vals = X_transformed.values[0]
                shap_values_arr = coefs * X_vals
                explanation_source = "Linear Coefficients x Scaled Input"

        # C. Generic fallback
        if shap_values_arr is None:
            explainer = shap.Explainer(classifier.predict_proba, X_transformed)
            res = explainer(X_transformed)
            if hasattr(res, "values"):
                vals = res.values
                if vals.ndim == 3:
                    shap_values_arr = vals[0, :, 1]
                else:
                    shap_values_arr = vals[0]
            explanation_source = "Generic Model Explainer"

    except Exception as e:
        # Fallback to global feature importance if local SHAP fails
        explanation_source = f"Global Permutation Fallback (SHAP error: {e})"
        if IMPORTANCE_PATH.exists():
            df_imp = pd.read_csv(IMPORTANCE_PATH)
            imp_map = dict(zip(df_imp["feature"], df_imp["importance"]))
            shap_values_arr = np.array([imp_map.get(col, 0.0) for col in transformed_feature_names])
        else:
            shap_values_arr = np.zeros(len(transformed_feature_names))

    if shap_values_arr is None or len(shap_values_arr) != len(transformed_feature_names):
        shap_values_arr = np.zeros(len(transformed_feature_names))

    # 4. Construct feature attribution records
    abs_shap = np.abs(shap_values_arr)
    max_abs = np.max(abs_shap) if len(abs_shap) > 0 and np.max(abs_shap) > 0 else 1.0

    records = []
    for col_name, shap_val, abs_val in zip(transformed_feature_names, shap_values_arr, abs_shap):
        raw_val = float(input_df[col_name].iloc[0]) if col_name in input_df.columns else float(X_transformed[col_name].iloc[0])
        
        # Determine Direction
        if shap_val > 0.0001:
            direction = "Toward Malware"
        elif shap_val < -0.0001:
            direction = "Toward Benign"
        else:
            direction = "Neutral"

        # Determine Magnitude Bucket
        rel_mag = abs_val / max_abs
        if rel_mag >= 0.50:
            magnitude = "High"
        elif rel_mag >= 0.20:
            magnitude = "Medium"
        else:
            magnitude = "Low"

        records.append({
            "name": col_name,
            "value": round(raw_val, 4),
            "shap_value": round(float(shap_val), 5),
            "abs_shap": float(abs_val),
            "direction": direction,
            "magnitude": magnitude,
            "impact_description": f"Pushes prediction {direction} (SHAP = {shap_val:+.4f}, Magnitude: {magnitude})",
            "source": explanation_source,
        })

    # 5. Sort by |SHAP value| descending and return top_k
    records.sort(key=lambda r: r["abs_shap"], reverse=True)
    top_records = records[:top_k]

    # Clean internal sorting key
    for r in top_records:
        r.pop("abs_shap", None)

    return top_records