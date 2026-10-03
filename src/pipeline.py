"""
Pipeline and Shared Utilities for Malware Classification Project.

Contains:
- load_data(): Loads CSV, validates paths and target column.
- dataset_summary(): Calculates comprehensive dataset statistics.
- get_feature_columns(): Extracts numeric feature columns (excluding Hash_md5_Name and Malware).
- FeatureEngineer: Sklearn transformer for PE header domain feature engineering.
- CorrelationFilter: Sklearn transformer for dropping collinear features (|r| > threshold).
"""

from pathlib import Path
from typing import Dict, List, Optional, Union, Any
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin

# Define project root relative to this file
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DEFAULT_DATA_PATH = DATA_DIR / "Malware-Benign.csv"


def load_data(file_path: Optional[Union[str, Path]] = None) -> pd.DataFrame:
    """
    Load the malware dataset from CSV.
    
    Args:
        file_path: Path to the CSV file. If None, defaults to data/Malware-Benign.csv
                   relative to the project root.
                   
    Returns:
        pd.DataFrame: Loaded dataset.
        
    Raises:
        FileNotFoundError: If the CSV file does not exist.
        ValueError: If the required target column 'Malware' is missing.
    """
    if file_path is None:
        target_path = DEFAULT_DATA_PATH
    else:
        target_path = Path(file_path)
        if not target_path.is_absolute():
            target_path = PROJECT_ROOT / target_path

    if not target_path.exists():
        raise FileNotFoundError(
            f"Dataset not found at '{target_path}'. "
            f"Please ensure 'Malware-Benign.csv' is placed inside '{DATA_DIR}'."
        )

    df = pd.read_csv(target_path)

    if "Malware" not in df.columns:
        raise ValueError(
            f"Target column 'Malware' not found in dataset at '{target_path}'. "
            f"Available columns: {list(df.columns)}"
        )

    return df


def get_feature_columns(df: pd.DataFrame) -> List[str]:
    """
    Get all numeric feature columns, excluding identifier 'Hash_md5_Name' and target 'Malware'.
    
    Args:
        df: Input DataFrame.
        
    Returns:
        List[str]: List of numeric feature column names.
    """
    excluded_columns = {"Hash_md5_Name", "Malware"}
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    return [col for col in numeric_cols if col not in excluded_columns]


def dataset_summary(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Generate a comprehensive summary of the dataset.
    
    Computes:
    - Total rows and columns
    - Malware count, benign count, and their percentages
    - Missing values count
    - Full-row duplicate count
    - Duplicate rows on feature columns only (excluding Hash_md5_Name and Malware)
    - Conflicting label statistics among identical feature rows
    - Number of numeric feature columns
    
    Args:
        df: Input DataFrame.
        
    Returns:
        Dict[str, Any]: Summary metrics dictionary.
    """
    total_rows = len(df)
    total_cols = len(df.columns)
    
    # Target counts
    if "Malware" in df.columns:
        malware_counts = df["Malware"].value_counts()
        malware_count = int(malware_counts.get(1, 0))
        benign_count = int(malware_counts.get(0, 0))
        malware_pct = round((malware_count / total_rows) * 100, 2) if total_rows > 0 else 0.0
        benign_pct = round((benign_count / total_rows) * 100, 2) if total_rows > 0 else 0.0
    else:
        malware_count = benign_count = 0
        malware_pct = benign_pct = 0.0

    # Missing values
    missing_values = int(df.isnull().sum().sum())
    
    # Full duplicate rows
    duplicate_full_rows = int(df.duplicated().sum())

    # Feature column duplicates
    feature_cols = get_feature_columns(df)
    feature_cols_count = len(feature_cols)

    # Duplicates on feature columns (df.duplicated gives redundant rows)
    dup_feature_rows = int(df.duplicated(subset=feature_cols).sum())
    
    # All rows involved in duplicate feature combinations
    dup_feature_mask = df.duplicated(subset=feature_cols, keep=False)
    dup_feature_all_occurrences = int(dup_feature_mask.sum())

    # Conflicting labels check
    conflicting_groups = 0
    conflicting_rows = 0
    if dup_feature_mask.sum() > 0 and "Malware" in df.columns:
        dup_df = df[dup_feature_mask]
        label_diversity = dup_df.groupby(feature_cols)["Malware"].nunique()
        conflicting_groups_mask = label_diversity > 1
        conflicting_groups = int(conflicting_groups_mask.sum())
        
        if conflicting_groups > 0:
            conflicting_sigs = label_diversity[conflicting_groups_mask].index
            if isinstance(conflicting_sigs, pd.MultiIndex):
                conflicting_rows = int(dup_df.set_index(feature_cols).index.isin(conflicting_sigs).sum())
            else:
                conflicting_rows = int(dup_df[feature_cols[0]].isin(conflicting_sigs).sum())

    summary = {
        "total_rows": total_rows,
        "total_columns": total_cols,
        "malware_count": malware_count,
        "benign_count": benign_count,
        "malware_percentage": malware_pct,
        "benign_percentage": benign_pct,
        "missing_values": missing_values,
        "duplicate_full_rows": duplicate_full_rows,
        "numeric_features_count": feature_cols_count,
        "duplicate_feature_rows": dup_feature_rows,
        "duplicate_feature_total_occurrences": dup_feature_all_occurrences,
        "has_conflicting_labels": conflicting_groups > 0,
        "conflicting_label_groups": conflicting_groups,
        "conflicting_label_rows": conflicting_rows,
    }
    return summary


class FeatureEngineer(BaseEstimator, TransformerMixin):
    """
    Custom scikit-learn transformer for PE header domain feature engineering.
    
    Adds domain-specific ratio and range features when the source columns exist:
    - CodeToImageRatio = SizeOfCode / (SizeOfImage + 1)
    - InitializedDataRatio = SizeOfInitializedData / (SizeOfImage + 1)
    - SectionRawSizeRange = SectionMaxRawsize - SectionMinRawsize
    - SectionVirtualSizeRange = SectionMaxVirtualsize - SectionMinVirtualsize
    - SectionEntropyRange = SectionMaxEntropy - SectionMinEntropy
    """
    
    def __init__(self):
        self.feature_names_in_ = None
        self.feature_names_out_ = None
        
    def fit(self, X: Union[pd.DataFrame, np.ndarray], y=None):
        if isinstance(X, pd.DataFrame):
            self.feature_names_in_ = list(X.columns)
            out_names = list(X.columns)
            if "SizeOfCode" in X.columns and "SizeOfImage" in X.columns:
                if "CodeToImageRatio" not in out_names:
                    out_names.append("CodeToImageRatio")
            if "SizeOfInitializedData" in X.columns and "SizeOfImage" in X.columns:
                if "InitializedDataRatio" not in out_names:
                    out_names.append("InitializedDataRatio")
            if "SectionMaxRawsize" in X.columns and "SectionMinRawsize" in X.columns:
                if "SectionRawSizeRange" not in out_names:
                    out_names.append("SectionRawSizeRange")
            if "SectionMaxVirtualsize" in X.columns and "SectionMinVirtualsize" in X.columns:
                if "SectionVirtualSizeRange" not in out_names:
                    out_names.append("SectionVirtualSizeRange")
            if "SectionMaxEntropy" in X.columns and "SectionMinEntropy" in X.columns:
                if "SectionEntropyRange" not in out_names:
                    out_names.append("SectionEntropyRange")
            self.feature_names_out_ = out_names
        return self

    def transform(self, X: Union[pd.DataFrame, np.ndarray]) -> pd.DataFrame:
        if isinstance(X, pd.DataFrame):
            X_out = X.copy()
        else:
            if self.feature_names_in_ is not None:
                X_out = pd.DataFrame(X, columns=self.feature_names_in_)
            else:
                X_out = pd.DataFrame(X)

        cols = set(X_out.columns)

        # CodeToImageRatio = SizeOfCode / (SizeOfImage + 1)
        if "SizeOfCode" in cols and "SizeOfImage" in cols:
            safe_denom = X_out["SizeOfImage"].astype(float) + 1.0
            safe_denom = safe_denom.replace(0, 1.0)
            X_out["CodeToImageRatio"] = (X_out["SizeOfCode"].astype(float) / safe_denom).fillna(0.0)

        # InitializedDataRatio = SizeOfInitializedData / (SizeOfImage + 1)
        if "SizeOfInitializedData" in cols and "SizeOfImage" in cols:
            safe_denom = X_out["SizeOfImage"].astype(float) + 1.0
            safe_denom = safe_denom.replace(0, 1.0)
            X_out["InitializedDataRatio"] = (X_out["SizeOfInitializedData"].astype(float) / safe_denom).fillna(0.0)

        # SectionRawSizeRange = SectionMaxRawsize - SectionMinRawsize
        if "SectionMaxRawsize" in cols and "SectionMinRawsize" in cols:
            X_out["SectionRawSizeRange"] = (
                X_out["SectionMaxRawsize"].astype(float) - X_out["SectionMinRawsize"].astype(float)
            ).fillna(0.0)

        # SectionVirtualSizeRange = SectionMaxVirtualsize - SectionMinVirtualsize
        if "SectionMaxVirtualsize" in cols and "SectionMinVirtualsize" in cols:
            X_out["SectionVirtualSizeRange"] = (
                X_out["SectionMaxVirtualsize"].astype(float) - X_out["SectionMinVirtualsize"].astype(float)
            ).fillna(0.0)

        # SectionEntropyRange = SectionMaxEntropy - SectionMinEntropy
        if "SectionMaxEntropy" in cols and "SectionMinEntropy" in cols:
            X_out["SectionEntropyRange"] = (
                X_out["SectionMaxEntropy"].astype(float) - X_out["SectionMinEntropy"].astype(float)
            ).fillna(0.0)

        # Replace any residual inf or -inf with 0.0
        X_out = X_out.replace([np.inf, -np.inf], 0.0)
        return X_out

    def get_feature_names_out(self, input_features=None) -> np.ndarray:
        if self.feature_names_out_ is not None:
            return np.array(self.feature_names_out_, dtype=object)
        if input_features is not None:
            return np.array(input_features, dtype=object)
        return np.array([], dtype=object)


class CorrelationFilter(BaseEstimator, TransformerMixin):
    """
    Custom scikit-learn transformer for removing collinear features.
    
    Fits strictly on training data:
    - Computes pairwise absolute Pearson correlation matrix.
    - Iterates deterministically over the upper triangle.
    - If |r| > threshold (default 0.95), flags the feature to be dropped.
    - Stores dropped_features_ and retained_features_.
    """
    
    def __init__(self, threshold: float = 0.95):
        self.threshold = threshold
        self.dropped_features_: List[str] = []
        self.retained_features_: List[str] = []
        self.feature_names_in_: Optional[List[str]] = None

    def fit(self, X: Union[pd.DataFrame, np.ndarray], y=None):
        if not isinstance(X, pd.DataFrame):
            if self.feature_names_in_ is not None:
                X_df = pd.DataFrame(X, columns=self.feature_names_in_)
            else:
                X_df = pd.DataFrame(X)
        else:
            X_df = X

        self.feature_names_in_ = list(X_df.columns)
        
        # Calculate correlation matrix
        corr_matrix = X_df.corr().abs()
        
        # Deterministic upper triangle examination
        upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
        
        # Columns that have any correlation strictly greater than threshold
        to_drop = [column for column in upper.columns if any(upper[column] > self.threshold)]
        
        self.dropped_features_ = to_drop
        self.retained_features_ = [col for col in X_df.columns if col not in to_drop]
        return self

    def transform(self, X: Union[pd.DataFrame, np.ndarray]) -> pd.DataFrame:
        if not isinstance(X, pd.DataFrame):
            if self.feature_names_in_ is not None:
                X_df = pd.DataFrame(X, columns=self.feature_names_in_)
            else:
                X_df = pd.DataFrame(X)
        else:
            X_df = X.copy()
            
        drop_cols = [col for col in self.dropped_features_ if col in X_df.columns]
        return X_df.drop(columns=drop_cols)

    def get_feature_names_out(self, input_features=None) -> np.ndarray:
        if self.retained_features_:
            return np.array(self.retained_features_, dtype=object)
        if input_features is not None:
            return np.array([f for f in input_features if f not in self.dropped_features_], dtype=object)
        return np.array([], dtype=object)
