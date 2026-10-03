"""
Training and Evaluation Script for Malware Classification.

Implements:
1. Stratified 80/20 train/test split (test indices saved to models/split_indices.json).
2. End-to-end scikit-learn Pipelines with custom domain transformers.
3. 5-fold Stratified CV model selection based on CV F1 score (tie-break: CV ROC-AUC).
4. Out-of-sample evaluation on untouched test set.
5. Feature importance extraction.
6. Artifact saving to models/ and outputs/.
"""

import sys
import json
import time
import warnings
import platform
from pathlib import Path
from typing import Dict, Any, List

# Suppress repetitive parallel worker warnings for clean stdout
warnings.filterwarnings("ignore", category=UserWarning)

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import sklearn
from sklearn.base import clone
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import VarianceThreshold, SelectFromModel
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.inspection import permutation_importance
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    balanced_accuracy_score,
    matthews_corrcoef,
    confusion_matrix,
    classification_report,
    roc_curve,
    precision_recall_curve,
)
import joblib

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.pipeline import (
    load_data,
    get_feature_columns,
    FeatureEngineer,
    CorrelationFilter,
)


def ensure_directories():
    """Ensure all destination directories exist."""
    dirs = [
        PROJECT_ROOT / "models",
        PROJECT_ROOT / "outputs" / "confusion_matrix",
        PROJECT_ROOT / "outputs" / "roc_curves",
        PROJECT_ROOT / "outputs" / "feature_importance",
        PROJECT_ROOT / "outputs" / "reports",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)


def build_pipeline_stages(classifier, include_scaler: bool = False) -> List[tuple]:
    """Construct pipeline steps according to specifications."""
    steps = [
        ("feature_engineer", FeatureEngineer()),
        ("variance_threshold", VarianceThreshold(threshold=0.0).set_output(transform="pandas")),
        ("correlation_filter", CorrelationFilter(threshold=0.95)),
        ("feature_selector", SelectFromModel(
            RandomForestClassifier(n_estimators=50, random_state=42, n_jobs=-1, class_weight="balanced")
        ).set_output(transform="pandas")),
    ]
    if include_scaler:
        steps.append(("scaler", StandardScaler().set_output(transform="pandas")))
    steps.append(("classifier", classifier))
    return steps


def main():
    start_time = time.time()
    ensure_directories()

    print("=" * 80)
    print(" MALWARE CLASSIFICATION: MODEL TRAINING & EVALUATION PIPELINE ")
    print("=" * 80)

    # 1. Load Data
    print("\n[Step 1] Loading dataset...")
    df = load_data()
    raw_feature_cols = get_feature_columns(df)
    X = df[raw_feature_cols]
    y = df["Malware"]

    print(f"  * Total Samples: {len(df):,}")
    print(f"  * Raw Feature Columns: {len(raw_feature_cols)}")
    print(f"  * Target Distribution: Malware={y.sum():,} ({y.mean()*100:.2f}%), Benign={(1-y).sum():,} ({(1-y).mean()*100:.2f}%)")

    # 2. Stratified Train / Test Split
    print("\n[Step 2] Splitting into Train (80%) and Test (20%) sets (Stratified, seed=42)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    split_indices = {
        "train_indices": [int(i) for i in X_train.index.tolist()],
        "test_indices": [int(i) for i in X_test.index.tolist()],
        "train_count": len(X_train),
        "test_count": len(X_test),
        "train_malware_count": int(y_train.sum()),
        "test_malware_count": int(y_test.sum()),
    }
    with open(PROJECT_ROOT / "models" / "split_indices.json", "w", encoding="utf-8") as f:
        json.dump(split_indices, f, indent=2)
    print(f"  * Train set shape: {X_train.shape} (Malware: {y_train.sum():,}, Benign: {(1-y_train).sum():,})")
    print(f"  * Test set shape:  {X_test.shape} (Malware: {y_test.sum():,}, Benign: {(1-y_test).sum():,})")
    print(f"  * Saved split indices to models/split_indices.json")

    # Save raw feature columns in order
    with open(PROJECT_ROOT / "models" / "feature_columns.json", "w", encoding="utf-8") as f:
        json.dump(raw_feature_cols, f, indent=2)
    print(f"  * Saved raw feature columns to models/feature_columns.json")

    # 3. Model Definitions
    print("\n[Step 3] Defining candidate classification pipelines...")
    models_dict = {
        "Logistic Regression": {
            "classifier": LogisticRegression(random_state=42, class_weight="balanced", max_iter=1000),
            "include_scaler": True,
        },
        "Decision Tree": {
            "classifier": DecisionTreeClassifier(random_state=42, class_weight="balanced", max_depth=12),
            "include_scaler": False,
        },
        "Random Forest": {
            "classifier": RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, class_weight="balanced", n_jobs=-1),
            "include_scaler": False,
        },
        "HistGradientBoosting": {
            "classifier": HistGradientBoostingClassifier(random_state=42, class_weight="balanced", max_iter=100),
            "include_scaler": False,
        },
    }

    pipelines = {}
    for name, config in models_dict.items():
        steps = build_pipeline_stages(config["classifier"], include_scaler=config["include_scaler"])
        pipelines[name] = sklearn.pipeline.Pipeline(steps)
        print(f"  * Initialized pipeline for '{name}'")

    # 4. Model Selection via 5-Fold Stratified CV on Training Data Only
    print("\n[Step 4] Running 5-fold Stratified Cross-Validation on Training Set...")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_results = {}

    for name, pipe in pipelines.items():
        print(f"  -> Cross-validating {name}...")
        scores = cross_validate(
            clone(pipe),
            X_train,
            y_train,
            cv=cv,
            scoring=["f1", "roc_auc", "accuracy", "precision", "recall"],
            n_jobs=1,
            return_train_score=False,
        )
        cv_results[name] = {
            "mean_f1": float(np.mean(scores["test_f1"])),
            "std_f1": float(np.std(scores["test_f1"])),
            "mean_roc_auc": float(np.mean(scores["test_roc_auc"])),
            "std_roc_auc": float(np.std(scores["test_roc_auc"])),
            "mean_accuracy": float(np.mean(scores["test_accuracy"])),
            "std_accuracy": float(np.std(scores["test_accuracy"])),
            "mean_precision": float(np.mean(scores["test_precision"])),
            "mean_recall": float(np.mean(scores["test_recall"])),
            "fold_f1_scores": [float(x) for x in scores["test_f1"]],
            "fold_roc_auc_scores": [float(x) for x in scores["test_roc_auc"]],
        }
        print(f"     Mean CV F1: {cv_results[name]['mean_f1']:.4f} (+/- {cv_results[name]['std_f1']:.4f}) | Mean CV ROC-AUC: {cv_results[name]['mean_roc_auc']:.4f}")

    # Determine winning model
    # Criterion: Highest mean CV F1 score, tie-break on mean CV ROC-AUC
    sorted_models = sorted(
        cv_results.keys(),
        key=lambda m: (cv_results[m]["mean_f1"], cv_results[m]["mean_roc_auc"]),
        reverse=True
    )
    best_model_name = sorted_models[0]
    selection_criterion = "Highest mean 5-fold Stratified CV F1 score on training set (tie-break: CV ROC-AUC)"
    print(f"\n  >>> Selected Winning Model: '{best_model_name}' <<<")
    print(f"  >>> Criterion: {selection_criterion}")

    # 5. Fit on Full Training Set and Evaluate on Untouched Test Set
    print("\n[Step 5] Fitting models on full training set and evaluating on untouched test set...")
    test_metrics = {}
    fitted_pipelines = {}
    test_predictions_dict = {}
    roc_data = {}

    for name, pipe in pipelines.items():
        print(f"  -> Fitting {name} on full train set...")
        t0 = time.time()
        pipe.fit(X_train, y_train)
        fit_duration = time.time() - t0
        fitted_pipelines[name] = pipe

        # Predictions on test set
        y_pred = pipe.predict(X_test)
        if hasattr(pipe, "predict_proba"):
            y_prob = pipe.predict_proba(X_test)[:, 1]
        elif hasattr(pipe, "decision_function"):
            decision = pipe.decision_function(X_test)
            y_prob = (decision - decision.min()) / (decision.max() - decision.min())
        else:
            y_prob = y_pred.astype(float)

        test_predictions_dict[name] = {
            "y_pred": y_pred,
            "y_prob": y_prob,
        }

        # Calculate metrics
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        roc_auc = roc_auc_score(y_test, y_prob)
        pr_auc = average_precision_score(y_test, y_prob)
        bal_acc = balanced_accuracy_score(y_test, y_pred)
        mcc = matthews_corrcoef(y_test, y_pred)
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()

        fpr, tpr, roc_thresh = roc_curve(y_test, y_prob)
        pr_curve_p, pr_curve_r, pr_thresh = precision_recall_curve(y_test, y_prob)

        roc_data[name] = {
            "fpr": [float(x) for x in fpr[::max(1, len(fpr)//100)]],
            "tpr": [float(x) for x in tpr[::max(1, len(tpr)//100)]],
            "roc_auc": float(roc_auc),
            "pr_precision": [float(x) for x in pr_curve_p[::max(1, len(pr_curve_p)//100)]],
            "pr_recall": [float(x) for x in pr_curve_r[::max(1, len(pr_curve_r)//100)]],
            "pr_auc": float(pr_auc),
        }

        cls_report_dict = classification_report(y_test, y_pred, target_names=["Benign (0)", "Malware (1)"], output_dict=True)
        cls_report_text = classification_report(y_test, y_pred, target_names=["Benign (0)", "Malware (1)"])

        test_metrics[name] = {
            "fit_time_seconds": round(fit_duration, 3),
            "accuracy": float(acc),
            "precision": float(prec),
            "recall": float(rec),
            "f1_score": float(f1),
            "roc_auc": float(roc_auc),
            "pr_auc": float(pr_auc),
            "balanced_accuracy": float(bal_acc),
            "matthews_corrcoef": float(mcc),
            "confusion_matrix": {
                "tp": int(tp),
                "tn": int(tn),
                "fp": int(fp),
                "fn": int(fn),
            },
            "classification_report": cls_report_dict,
            "classification_report_text": cls_report_text,
        }

        print(f"     Test F1: {f1:.4f} | Test ROC-AUC: {roc_auc:.4f} | Test Acc: {acc:.4f} | MCC: {mcc:.4f} | (TP={tp}, TN={tn}, FP={fp}, FN={fn})")

    # 6. Feature Selection Tracking & Feature Importance for Final Model
    print(f"\n[Step 6] Analyzing feature transformation stages & importance for '{best_model_name}'...")
    final_pipeline = fitted_pipelines[best_model_name]

    # Trace feature counts at each stage on training data
    fe_step = final_pipeline.named_steps["feature_engineer"]
    vt_step = final_pipeline.named_steps["variance_threshold"]
    cf_step = final_pipeline.named_steps["correlation_filter"]
    sfm_step = final_pipeline.named_steps["feature_selector"]

    # 1. Feature Engineering
    X_tr_fe = fe_step.transform(X_train)
    all_fe_cols = list(X_tr_fe.columns)
    engineered_cols = [c for c in all_fe_cols if c not in raw_feature_cols]

    # 2. Variance Threshold
    vt_support = vt_step.get_support()
    vt_kept_cols = [col for col, sup in zip(all_fe_cols, vt_support) if sup]
    vt_removed_cols = [col for col, sup in zip(all_fe_cols, vt_support) if not sup]

    # 3. Correlation Filter
    cf_removed_cols = list(cf_step.dropped_features_)
    cf_kept_cols = list(cf_step.retained_features_)

    # 4. SelectFromModel
    sfm_support = sfm_step.get_support()
    sfm_selected_cols = [col for col, sup in zip(cf_kept_cols, sfm_support) if sup]
    sfm_removed_cols = [col for col, sup in zip(cf_kept_cols, sfm_support) if not sup]

    selected_features_info = {
        "raw_features_count": len(raw_feature_cols),
        "raw_features": raw_feature_cols,
        "engineered_features_count": len(engineered_cols),
        "engineered_features": engineered_cols,
        "post_feature_engineer_count": len(all_fe_cols),
        "variance_threshold_removed_count": len(vt_removed_cols),
        "variance_threshold_removed_features": vt_removed_cols,
        "post_variance_threshold_count": len(vt_kept_cols),
        "correlation_filter_removed_count": len(cf_removed_cols),
        "correlation_filter_removed_features": cf_removed_cols,
        "post_correlation_filter_count": len(cf_kept_cols),
        "select_from_model_removed_count": len(sfm_removed_cols),
        "final_selected_features_count": len(sfm_selected_cols),
        "final_selected_features": sfm_selected_cols,
    }

    with open(PROJECT_ROOT / "models" / "selected_features.json", "w", encoding="utf-8") as f:
        json.dump(selected_features_info, f, indent=2)
    print(f"  * Stage Summary: {len(raw_feature_cols)} raw -> +{len(engineered_cols)} eng ({len(all_fe_cols)}) -> -{len(vt_removed_cols)} zero-var ({len(vt_kept_cols)}) -> -{len(cf_removed_cols)} corr ({len(cf_kept_cols)}) -> {len(sfm_selected_cols)} final selected features.")

    # Calculate Feature Importance for Final Model
    classifier_step = final_pipeline.named_steps["classifier"]
    
    # Pass X_train through pipeline stages up to the classifier
    X_curr = X_train
    for step_name, step_transformer in final_pipeline.steps[:-1]:
        X_curr = step_transformer.transform(X_curr)

    if hasattr(classifier_step, "feature_importances_"):
        raw_importances = classifier_step.feature_importances_
        importance_type = "native_tree_feature_importances"
    elif hasattr(classifier_step, "coef_"):
        raw_importances = np.abs(classifier_step.coef_[0])
        importance_type = "absolute_logistic_coefficients"
    else:
        # Permutation importance on transformed training data
        print("  -> Computing permutation importance on transformed training data...")
        perm_res = permutation_importance(classifier_step, X_curr, y_train, n_repeats=5, random_state=42, n_jobs=-1)
        raw_importances = perm_res.importances_mean
        importance_type = "permutation_importance_mean"

    # Normalize to relative percentages / sum to 1
    total_imp = np.sum(raw_importances)
    if total_imp > 0:
        normalized_importances = raw_importances / total_imp
    else:
        normalized_importances = raw_importances

    df_importance = pd.DataFrame({
        "feature": sfm_selected_cols,
        "importance": raw_importances,
        "relative_importance": normalized_importances,
    }).sort_values(by="importance", ascending=False).reset_index(drop=True)

    # Save feature importance to models/ and outputs/
    df_importance.to_csv(PROJECT_ROOT / "models" / "feature_importance.csv", index=False)
    df_importance.to_csv(PROJECT_ROOT / "outputs" / "feature_importance" / "feature_importances.csv", index=False)
    print(f"  * Computed {importance_type}. Saved to models/feature_importance.csv.")

    # 7. Save Models and Metadata
    print("\n[Step 7] Saving artifacts to models/ and outputs/...")
    
    # Save final model pipeline
    joblib.dump(final_pipeline, PROJECT_ROOT / "models" / "final_model.pkl")
    print("  * Saved full pipeline to models/final_model.pkl")

    # Save feature selector
    joblib.dump(sfm_step, PROJECT_ROOT / "models" / "feature_selector.pkl")
    print("  * Saved feature selector to models/feature_selector.pkl")

    # Save test predictions for best model
    best_preds = test_predictions_dict[best_model_name]
    df_test_preds = pd.DataFrame({
        "original_index": X_test.index,
        "actual": y_test.values,
        "predicted": best_preds["y_pred"],
        "malware_probability": best_preds["y_prob"],
    })
    df_test_preds.to_csv(PROJECT_ROOT / "models" / "test_predictions.csv", index=False)
    print("  * Saved test set predictions to models/test_predictions.csv")

    # Save combined model metrics
    combined_metrics = {
        "selection_criterion": selection_criterion,
        "selected_model": best_model_name,
        "cross_validation_train": cv_results,
        "test_set_evaluation": test_metrics,
    }
    with open(PROJECT_ROOT / "models" / "model_metrics.json", "w", encoding="utf-8") as f:
        json.dump(combined_metrics, f, indent=2)

    # Save ROC curve data
    with open(PROJECT_ROOT / "models" / "roc_data.json", "w", encoding="utf-8") as f:
        json.dump(roc_data, f, indent=2)

    # Save training metadata
    metadata = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "random_seed": 42,
        "selection_criterion": selection_criterion,
        "selected_model": best_model_name,
        "total_dataset_rows": len(df),
        "train_rows": len(X_train),
        "test_rows": len(X_test),
        "raw_features_count": len(raw_feature_cols),
        "final_selected_features_count": len(sfm_selected_cols),
        "libraries": {
            "python_version": platform.python_version(),
            "scikit_learn_version": sklearn.__version__,
            "joblib_version": joblib.__version__,
            "pandas_version": pd.__version__,
            "numpy_version": np.__version__,
            "matplotlib_version": matplotlib.__version__,
        },
    }
    with open(PROJECT_ROOT / "models" / "training_metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print("  * Saved metadata to models/training_metadata.json")

    # Save CSV comparison report
    rows_comparison = []
    for m in models_dict.keys():
        cv_m = cv_results[m]
        t_m = test_metrics[m]
        rows_comparison.append({
            "Model": m,
            "CV F1 (Mean)": round(cv_m["mean_f1"], 4),
            "CV F1 (Std)": round(cv_m["std_f1"], 4),
            "CV ROC-AUC": round(cv_m["mean_roc_auc"], 4),
            "Test Accuracy": round(t_m["accuracy"], 4),
            "Test Precision": round(t_m["precision"], 4),
            "Test Recall": round(t_m["recall"], 4),
            "Test F1": round(t_m["f1_score"], 4),
            "Test ROC-AUC": round(t_m["roc_auc"], 4),
            "Test PR-AUC": round(t_m["pr_auc"], 4),
            "Test Balanced Acc": round(t_m["balanced_accuracy"], 4),
            "Test MCC": round(t_m["matthews_corrcoef"], 4),
            "TP": t_m["confusion_matrix"]["tp"],
            "TN": t_m["confusion_matrix"]["tn"],
            "FP": t_m["confusion_matrix"]["fp"],
            "FN": t_m["confusion_matrix"]["fn"],
            "Is Selected": "YES" if m == best_model_name else "NO",
        })
    df_comparison = pd.DataFrame(rows_comparison)
    df_comparison.to_csv(PROJECT_ROOT / "outputs" / "reports" / "model_comparison_report.csv", index=False)
    print("  * Saved report to outputs/reports/model_comparison_report.csv")

    # Save classification reports text/json
    cls_reports = {m: test_metrics[m]["classification_report_text"] for m in models_dict.keys()}
    with open(PROJECT_ROOT / "outputs" / "reports" / "classification_reports.json", "w", encoding="utf-8") as f:
        json.dump({m: test_metrics[m]["classification_report"] for m in models_dict.keys()}, f, indent=2)

    # 8. Generate Visualizations into outputs/
    print("\n[Step 8] Generating high-resolution plots into outputs/...")

    # A. Confusion Matrix Plots
    for name, m_data in test_metrics.items():
        cm = np.array([
            [m_data["confusion_matrix"]["tn"], m_data["confusion_matrix"]["fp"]],
            [m_data["confusion_matrix"]["fn"], m_data["confusion_matrix"]["tp"]],
        ])
        fig, ax = plt.subplots(figsize=(6, 5), dpi=300)
        im = ax.imshow(cm, cmap="Blues", interpolation="nearest")
        fig.colorbar(im, ax=ax)
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(["Benign (0)", "Malware (1)"], fontsize=11)
        ax.set_yticklabels(["Benign (0)", "Malware (1)"], fontsize=11)
        ax.set_xlabel("Predicted Label", fontsize=12, fontweight="bold", labelpad=8)
        ax.set_ylabel("True Label", fontsize=12, fontweight="bold", labelpad=8)
        ax.set_title(f"Confusion Matrix: {name}\n(Test Set, N={len(X_test):,})", fontsize=13, fontweight="bold", pad=12)

        # Annotate cell numbers
        thresh = cm.max() / 2.0
        for i in range(2):
            for j in range(2):
                val = cm[i, j]
                pct = val / cm.sum() * 100
                color = "white" if val > thresh else "black"
                ax.text(j, i, f"{val:,}\n({pct:.1f}%)", ha="center", va="center", color=color, fontsize=12, fontweight="bold")

        plt.tight_layout()
        safe_name = name.lower().replace(" ", "_")
        plt.savefig(PROJECT_ROOT / "outputs" / "confusion_matrix" / f"confusion_matrix_{safe_name}.png")
        plt.close()

    # Comparison 2x2 Confusion Matrices Grid
    fig, axes = plt.subplots(2, 2, figsize=(11, 9), dpi=300)
    for ax, (name, m_data) in zip(axes.ravel(), test_metrics.items()):
        cm = np.array([
            [m_data["confusion_matrix"]["tn"], m_data["confusion_matrix"]["fp"]],
            [m_data["confusion_matrix"]["fn"], m_data["confusion_matrix"]["tp"]],
        ])
        im = ax.imshow(cm, cmap="Blues", interpolation="nearest")
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(["Benign", "Malware"], fontsize=9)
        ax.set_yticklabels(["Benign", "Malware"], fontsize=9)
        ax.set_xlabel("Predicted", fontsize=10)
        ax.set_ylabel("True", fontsize=10)
        tag = " [SELECTED]" if name == best_model_name else ""
        ax.set_title(f"{name}{tag}\nF1: {m_data['f1_score']:.4f} | Acc: {m_data['accuracy']:.4f}", fontsize=11, fontweight="bold")
        thresh = cm.max() / 2.0
        for i in range(2):
            for j in range(2):
                val = cm[i, j]
                color = "white" if val > thresh else "black"
                ax.text(j, i, f"{val:,}", ha="center", va="center", color=color, fontsize=11, fontweight="bold")
    plt.tight_layout()
    plt.savefig(PROJECT_ROOT / "outputs" / "confusion_matrix" / "confusion_matrices_all.png")
    plt.close()

    # B. ROC Curves & PR Curves
    fig, ax = plt.subplots(figsize=(8, 6), dpi=300)
    for name in models_dict.keys():
        preds = test_predictions_dict[name]
        fpr, tpr, _ = roc_curve(y_test, preds["y_prob"])
        auc_score = test_metrics[name]["roc_auc"]
        style = "-" if name == best_model_name else "--"
        width = 2.5 if name == best_model_name else 1.5
        ax.plot(fpr, tpr, style, linewidth=width, label=f"{name} (AUC = {auc_score:.4f})")
    ax.plot([0, 1], [0, 1], "k:", label="Random Chance (AUC = 0.5000)", alpha=0.6)
    ax.set_xlabel("False Positive Rate (1 - Specificity)", fontsize=11, fontweight="bold")
    ax.set_ylabel("True Positive Rate (Sensitivity / Recall)", fontsize=11, fontweight="bold")
    ax.set_title("ROC Curves Comparison (Untouched Test Set)", fontsize=13, fontweight="bold", pad=12)
    ax.legend(loc="lower right", fontsize=10)
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(PROJECT_ROOT / "outputs" / "roc_curves" / "roc_curves_all.png")
    plt.close()

    fig, ax = plt.subplots(figsize=(8, 6), dpi=300)
    for name in models_dict.keys():
        preds = test_predictions_dict[name]
        p_c, r_c, _ = precision_recall_curve(y_test, preds["y_prob"])
        pr_auc = test_metrics[name]["pr_auc"]
        style = "-" if name == best_model_name else "--"
        width = 2.5 if name == best_model_name else 1.5
        ax.plot(r_c, p_c, style, linewidth=width, label=f"{name} (PR-AUC = {pr_auc:.4f})")
    baseline = y_test.mean()
    ax.axhline(baseline, color="k", linestyle=":", label=f"Baseline Prevalence ({baseline:.4f})", alpha=0.6)
    ax.set_xlabel("Recall", fontsize=11, fontweight="bold")
    ax.set_ylabel("Precision", fontsize=11, fontweight="bold")
    ax.set_title("Precision-Recall Curves Comparison (Untouched Test Set)", fontsize=13, fontweight="bold", pad=12)
    ax.legend(loc="lower left", fontsize=10)
    ax.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(PROJECT_ROOT / "outputs" / "roc_curves" / "pr_curves_all.png")
    plt.close()

    # C. Feature Importance Plot
    top_n = min(15, len(df_importance))
    df_top = df_importance.head(top_n).sort_values("importance", ascending=True)
    fig, ax = plt.subplots(figsize=(9, 6), dpi=300)
    bars = ax.barh(df_top["feature"], df_top["importance"], color="#1f77b4", edgecolor="#0e4166", alpha=0.85)
    ax.set_xlabel("Importance Score", fontsize=11, fontweight="bold")
    ax.set_title(f"Top {top_n} Features: {best_model_name}\n({importance_type.replace('_', ' ').title()})", fontsize=13, fontweight="bold", pad=12)
    ax.grid(axis="x", alpha=0.3)
    for bar in bars:
        w = bar.get_width()
        ax.text(w + (df_top["importance"].max() * 0.01), bar.get_y() + bar.get_height()/2, f"{w:.4f}", va="center", fontsize=9, fontweight="bold")
    plt.tight_layout()
    plt.savefig(PROJECT_ROOT / "outputs" / "feature_importance" / "top_features.png")
    plt.close()

    total_elapsed = time.time() - start_time
    print(f"\n[Step 9] Training & evaluation pipeline completed in {total_elapsed:.2f} seconds.")
    print("=" * 80)


if __name__ == "__main__":
    main()
