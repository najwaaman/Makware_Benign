"""
Model Training, Evaluation, Comparison, Feature Importance, and Error Analysis Views.
"""

import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Dict, Any, Optional

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

COLOR_MALWARE = "#EF4444"
COLOR_BENIGN = "#3B82F6"


def render_model_training_page(metadata: Optional[Dict[str, Any]], metrics: Optional[Dict[str, Any]], project_root: Path):
    st.markdown('<div class="main-title">Model Training & Cross-Validation</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">Candidate classifiers, pipeline architecture, 5-fold stratified CV, and selection criteria</div>', unsafe_allow_html=True)

    if not metrics or not metadata:
        st.error("⚠️ Model training artifacts not found. Please run `python train_model.py` to generate training artifacts.")
        return

    # Architecture Overview
    st.subheader("1. Scikit-Learn Pipeline Architecture")
    st.markdown(
        textwrap.dedent(
            """
            Each candidate model is embedded inside an automated scikit-learn `Pipeline` to strictly prevent data leakage:
            """
        )
    )

    steps_html = textwrap.dedent(
        """
        <div style="display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin: 15px 0;">
            <span class="badge" style="background-color: #E2E8F0; color: #1E293B; padding: 8px 12px; font-size: 0.85rem;">1. FeatureEngineer (5 PE ratios)</span>
            <span style="font-weight: bold; color: #94A3B8;">&rarr;</span>
            <span class="badge" style="background-color: #E2E8F0; color: #1E293B; padding: 8px 12px; font-size: 0.85rem;">2. VarianceThreshold (Zero-Var)</span>
            <span style="font-weight: bold; color: #94A3B8;">&rarr;</span>
            <span class="badge" style="background-color: #E2E8F0; color: #1E293B; padding: 8px 12px; font-size: 0.85rem;">3. CorrelationFilter (|r| &le; 0.95)</span>
            <span style="font-weight: bold; color: #94A3B8;">&rarr;</span>
            <span class="badge" style="background-color: #E2E8F0; color: #1E293B; padding: 8px 12px; font-size: 0.85rem;">4. SelectFromModel (RandomForest)</span>
            <span style="font-weight: bold; color: #94A3B8;">&rarr;</span>
            <span class="badge" style="background-color: #DBEAFE; color: #1E40AF; padding: 8px 12px; font-size: 0.85rem;">5. Classifier</span>
        </div>
        """
    )
    st.markdown(steps_html, unsafe_allow_html=True)

    st.divider()

    # Candidate Models & CV Setup
    st.subheader("2. 5-Fold Stratified Cross-Validation Setup")
    st.write(
        f"""
        - **Training Partition Size:** {metadata.get('train_rows', 15688):,} samples (80% of total dataset).
        - **Cross-Validation Scheme:** 5-fold Stratified K-Fold (`n_splits=5, shuffle=True, random_state=42`).
        - **Class Weighting:** `class_weight='balanced'` applied to all supported algorithms to handle ~3:1 malware prevalence.
        - **Selection Criterion:** **{metrics.get('selection_criterion', 'Highest mean 5-fold Stratified CV F1 score on training set (tie-break: CV ROC-AUC)')}**
        - **Winning Selected Model:** **`{metrics.get('selected_model', 'HistGradientBoosting')}`**
        """
    )

    # CV Scores Table
    cv_data = metrics.get("cross_validation_train", {})
    if cv_data:
        cv_rows = []
        for model_name, cv_res in cv_data.items():
            cv_rows.append({
                "Model": model_name,
                "CV F1 (Mean)": f"{cv_res['mean_f1']:.4f}",
                "CV F1 (Std)": f"± {cv_res['std_f1']:.4f}",
                "CV ROC-AUC (Mean)": f"{cv_res['mean_roc_auc']:.4f}",
                "CV Accuracy (Mean)": f"{cv_res['mean_accuracy']:.4f}",
                "CV Precision (Mean)": f"{cv_res['mean_precision']:.4f}",
                "CV Recall (Mean)": f"{cv_res['mean_recall']:.4f}",
                "Is Selected": "⭐ YES" if model_name == metrics.get("selected_model") else "NO",
            })
        st.dataframe(pd.DataFrame(cv_rows), use_container_width=True)

    st.divider()

    # Retrain Models Action Button
    st.subheader("3. Pipeline Retraining Control")
    st.warning("⚠️ Retraining executes 5-fold cross-validation on all 4 pipelines and updates all models in `models/`.")
    confirm_retrain = st.checkbox("I confirm that I want to retrain all models on the training dataset.", value=False)
    
    if st.button("🚀 Retrain Models", disabled=not confirm_retrain, type="primary"):
        with st.spinner("Retraining all candidate pipelines with 5-fold CV... (approx. 45-60s)"):
            try:
                res = subprocess.run([sys.executable, "train_model.py"], cwd=str(project_root), capture_output=True, text=True, check=True)
                st.success("✅ Models successfully retrained! Reloading cached artifacts...")
                st.cache_data.clear()
                st.rerun()
            except subprocess.CalledProcessError as e:
                st.error(f"❌ Retraining failed with error: {e.stderr}")


def render_model_evaluation_page(metrics: Optional[Dict[str, Any]], roc_data: Optional[Dict[str, Any]], split_info: Optional[Dict[str, Any]]):
    st.markdown('<div class="main-title">Out-of-Sample Model Evaluation</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">Rigorous evaluation on the untouched 20% test partition (N = 3,923)</div>', unsafe_allow_html=True)

    if not metrics:
        st.error("⚠️ Evaluation metrics not found. Please ensure `models/model_metrics.json` exists.")
        return

    test_metrics = metrics.get("test_set_evaluation", {})
    if not test_metrics:
        st.error("⚠️ Test set metrics not available.")
        return

    # Imbalance context banner
    st.info(
        "💡 **Class Imbalance Notice:** The dataset has ~74.4% Malware and ~25.6% Benign samples. "
        "A trivial baseline predicting only Malware would achieve ~74.4% accuracy. "
        "Therefore, **F1-Score, PR-AUC, Recall (Sensitivity), and MCC (Matthews Correlation Coefficient)** "
        "are prioritized as the primary evaluation metrics."
    )

    # Model Selector
    model_names = list(test_metrics.keys())
    best_model = metrics.get("selected_model", model_names[0])
    default_idx = model_names.index(best_model) if best_model in model_names else 0
    
    selected_model = st.selectbox("Select model to evaluate:", options=model_names, index=default_idx)
    m_eval = test_metrics[selected_model]
    cm_data = m_eval["confusion_matrix"]

    st.divider()

    # KPI Metric Cards
    k1, k2, k3, k4, k5, k6 = st.columns(6)
    k1.metric("F1 Score", f"{m_eval['f1_score']:.4f}")
    k2.metric("ROC-AUC", f"{m_eval['roc_auc']:.4f}")
    k3.metric("PR-AUC", f"{m_eval['pr_auc']:.4f}")
    k4.metric("Recall (Sensitivity)", f"{m_eval['recall']:.4f}")
    k5.metric("Precision", f"{m_eval['precision']:.4f}")
    k6.metric("MCC", f"{m_eval['matthews_corrcoef']:.4f}")

    st.markdown("<br>", unsafe_allow_html=True)

    # Confusion Matrix & Classification Report Grid
    col_cm, col_report = st.columns([1, 1])

    with col_cm:
        st.subheader("Confusion Matrix")
        tp, tn, fp, fn = cm_data["tp"], cm_data["tn"], cm_data["fp"], cm_data["fn"]
        total = tp + tn + fp + fn
        
        cm_matrix = np.array([[tn, fp], [fn, tp]])
        fig_cm = px.imshow(
            cm_matrix,
            labels=dict(x="Predicted Label", y="True Label", color="Count"),
            x=["Benign (0)", "Malware (1)"],
            y=["Benign (0)", "Malware (1)"],
            text_auto=True,
            color_continuous_scale="Blues",
            title=f"Confusion Matrix: {selected_model}",
            height=380,
        )
        st.plotly_chart(fig_cm, use_container_width=True)

        st.markdown(
            f"""
            - **True Positives (TP):** `{tp:,}` (Correctly identified Malware)
            - **True Negatives (TN):** `{tn:,}` (Correctly identified Benign)
            - **False Positives (FP):** `{fp:,}` (Benign flagged as Malware - Type I Error)
            - **False Negatives (FN):** `{fn:,}` (Malware missed - Type II Error / Highest Risk)
            """
        )

    with col_report:
        st.subheader("Classification Report")
        cls_dict = m_eval.get("classification_report", {})
        if cls_dict:
            report_rows = []
            for target_class in ["Benign (0)", "Malware (1)"]:
                if target_class in cls_dict:
                    report_rows.append({
                        "Class": target_class,
                        "Precision": f"{cls_dict[target_class]['precision']:.4f}",
                        "Recall": f"{cls_dict[target_class]['recall']:.4f}",
                        "F1-Score": f"{cls_dict[target_class]['f1-score']:.4f}",
                        "Support": f"{int(cls_dict[target_class]['support']):,}",
                    })
            st.table(pd.DataFrame(report_rows))
            
            st.markdown("#### Aggregate Metrics")
            st.write(f"- **Macro Average F1:** `{cls_dict.get('macro avg', {}).get('f1-score', 0):.4f}`")
            st.write(f"- **Weighted Average F1:** `{cls_dict.get('weighted avg', {}).get('f1-score', 0):.4f}`")
            st.write(f"- **Balanced Accuracy:** `{m_eval.get('balanced_accuracy', 0):.4f}`")

    st.divider()

    # ROC & PR Curves
    st.subheader("ROC & Precision-Recall Curves")
    if roc_data and selected_model in roc_data:
        r_model = roc_data[selected_model]
        c_roc, c_pr = st.columns(2)

        with c_roc:
            fig_roc = go.Figure()
            fig_roc.add_trace(go.Scatter(
                x=r_model["fpr"], y=r_model["tpr"], mode="lines",
                name=f"{selected_model} (AUC = {r_model['roc_auc']:.4f})",
                line=dict(color="#2563EB", width=2.5)
            ))
            fig_roc.add_trace(go.Scatter(
                x=[0, 1], y=[0, 1], mode="lines",
                name="Random Chance (AUC = 0.5000)",
                line=dict(color="#94A3B8", dash="dash")
            ))
            fig_roc.update_layout(
                title="Receiver Operating Characteristic (ROC)",
                xaxis_title="False Positive Rate",
                yaxis_title="True Positive Rate (Recall)",
                height=400,
            )
            st.plotly_chart(fig_roc, use_container_width=True)

        with c_pr:
            fig_pr = go.Figure()
            fig_pr.add_trace(go.Scatter(
                x=r_model["pr_recall"], y=r_model["pr_precision"], mode="lines",
                name=f"{selected_model} (PR-AUC = {r_model['pr_auc']:.4f})",
                line=dict(color="#10B981", width=2.5)
            ))
            baseline = 2920 / 3923  # Test set malware prevalence
            fig_pr.add_trace(go.Scatter(
                x=[0, 1], y=[baseline, baseline], mode="lines",
                name=f"Baseline Prevalence ({baseline:.4f})",
                line=dict(color="#94A3B8", dash="dash")
            ))
            fig_pr.update_layout(
                title="Precision-Recall Curve",
                xaxis_title="Recall",
                yaxis_title="Precision",
                height=400,
            )
            st.plotly_chart(fig_pr, use_container_width=True)


def render_model_comparison_page(metrics: Optional[Dict[str, Any]]):
    st.markdown('<div class="main-title">Multi-Model Comparison & Benchmarking</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">Comparative performance matrix across all 4 machine learning pipelines</div>', unsafe_allow_html=True)

    if not metrics:
        st.error("⚠️ Metrics artifact not found.")
        return

    best_model = metrics.get("selected_model", "Unknown")
    criterion = metrics.get("selection_criterion", "Highest mean CV F1 score")

    # Selection Criterion Callout
    st.success(f"🏆 **Winning Model:** `{best_model}` &nbsp;|&nbsp; **Selection Criterion:** {criterion}")

    cv_dict = metrics.get("cross_validation_train", {})
    test_dict = metrics.get("test_set_evaluation", {})

    comp_rows = []
    for m in test_dict.keys():
        cv_m = cv_dict.get(m, {})
        t_m = test_dict.get(m, {})
        comp_rows.append({
            "Model": m,
            "CV F1 (Mean)": cv_m.get("mean_f1", 0.0),
            "CV ROC-AUC": cv_m.get("mean_roc_auc", 0.0),
            "Test Accuracy": t_m.get("accuracy", 0.0),
            "Test Precision": t_m.get("precision", 0.0),
            "Test Recall": t_m.get("recall", 0.0),
            "Test F1 Score": t_m.get("f1_score", 0.0),
            "Test ROC-AUC": t_m.get("roc_auc", 0.0),
            "Test PR-AUC": t_m.get("pr_auc", 0.0),
            "Test MCC": t_m.get("matthews_corrcoef", 0.0),
            "Status": "⭐ Selected" if m == best_model else "Candidate",
        })

    df_comp = pd.DataFrame(comp_rows)

    # Format dataframe for display
    st.subheader("1. Comprehensive Model Performance Matrix")
    st.dataframe(
        df_comp.style.format({
            "CV F1 (Mean)": "{:.4f}",
            "CV ROC-AUC": "{:.4f}",
            "Test Accuracy": "{:.4f}",
            "Test Precision": "{:.4f}",
            "Test Recall": "{:.4f}",
            "Test F1 Score": "{:.4f}",
            "Test ROC-AUC": "{:.4f}",
            "Test PR-AUC": "{:.4f}",
            "Test MCC": "{:.4f}",
        }),
        use_container_width=True,
    )

    st.divider()

    # Interactive Bar Charts Comparison
    st.subheader("2. Visual Metric Comparisons")
    selected_metrics_plot = st.multiselect(
        "Select metrics to compare in bar chart:",
        options=["Test F1 Score", "Test ROC-AUC", "Test PR-AUC", "Test Accuracy", "Test Precision", "Test Recall", "Test MCC"],
        default=["Test F1 Score", "Test ROC-AUC", "Test Recall"],
    )

    if selected_metrics_plot:
        df_plot = df_comp.melt(id_vars=["Model"], value_vars=selected_metrics_plot, var_name="Metric", value_name="Score")
        fig_comp = px.bar(
            df_plot,
            x="Model",
            y="Score",
            color="Metric",
            barmode="group",
            text_auto=".4f",
            title="Candidate Model Benchmark by Metric",
            height=450,
        )
        fig_comp.update_yaxes(range=[0.85, 1.0])
        st.plotly_chart(fig_comp, use_container_width=True)


def render_feature_importance_page(df_importance: Optional[pd.DataFrame], metadata: Optional[Dict[str, Any]]):
    st.markdown('<div class="main-title">Feature Importance Analysis</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">Identification of dominant static PE header predictors for the final model</div>', unsafe_allow_html=True)

    if df_importance is None or df_importance.empty:
        st.error("⚠️ Feature importance data not found. Please ensure `models/feature_importance.csv` exists.")
        return

    # Mandatory Caution Note
    st.warning(
        "📌 **Important Interpretation Notice:** Feature importance indicates how strongly a feature contributed to the model's predictions. "
        "It does not by itself prove that the feature causes malware."
    )

    # Toggle Top N
    top_n = st.radio("Display Depth:", options=[10, 16, 20], index=0, horizontal=True)
    df_top = df_importance.head(top_n).sort_values("importance", ascending=True)

    # Plotly Horizontal Bar Chart
    fig_imp = px.bar(
        df_top,
        x="importance",
        y="feature",
        orientation="h",
        text_auto=".4f",
        title=f"Top {top_n} Most Important Predictors ({metadata.get('selected_model', 'Winning Model') if metadata else 'Model'})",
        labels={"importance": "Importance Score (Mean Permutation / Gini)", "feature": "PE Header Feature"},
        color="importance",
        color_continuous_scale="Blues",
        height=max(400, top_n * 25),
    )
    st.plotly_chart(fig_imp, use_container_width=True)

    st.subheader("Feature Importance Table")
    st.dataframe(
        df_importance.style.format({
            "importance": "{:.6f}",
            "relative_importance": "{:.2%}",
        }),
        use_container_width=True,
    )

    st.divider()

    # Local vs Global Feature Importance Deep-Dive
    st.subheader("🧠 Local (SHAP) vs. Global Feature Importance")
    st.markdown(
        textwrap.dedent(
            """
            In cybersecurity machine learning, understanding both global trends and individual file decisions is critical:
            """
        )
    )
    
    col_g, col_l = st.columns(2)
    with col_g:
        st.markdown(
            textwrap.dedent(
                """
                <div style="background: #131C2E; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 10px; padding: 1.2rem;">
                    <h4 style="color: #00D2FF; margin-top: 0;">🌐 Global Feature Importance</h4>
                    <ul style="color: #CBD5E1; font-size: 0.9rem; line-height: 1.6; margin-bottom: 0;">
                        <li><strong>Scope:</strong> Dataset-wide across all 15,688 training samples.</li>
                        <li><strong>Method:</strong> Permutation importance and Random Forest Gini split gain.</li>
                        <li><strong>Interpretation:</strong> Identifies which PE header attributes the model depends on <em>on average</em> to separate malware from benign software.</li>
                        <li><strong>Limitation:</strong> Does not reveal how an individual file was evaluated.</li>
                    </ul>
                </div>
                """
            ),
            unsafe_allow_html=True,
        )
    with col_l:
        st.markdown(
            textwrap.dedent(
                """
                <div style="background: #131C2E; border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 10px; padding: 1.2rem;">
                    <h4 style="color: #10B981; margin-top: 0;">🎯 Local (SHAP) Attribution</h4>
                    <ul style="color: #CBD5E1; font-size: 0.9rem; line-height: 1.6; margin-bottom: 0;">
                        <li><strong>Scope:</strong> Single sample inference (e.g. your uploaded <code>.exe</code> file).</li>
                        <li><strong>Method:</strong> Shapley Additive exPlanations (<code>shap.TreeExplainer</code>).</li>
                        <li><strong>Interpretation:</strong> Computes the exact positive (toward Malware) or negative (toward Benign) push that each specific header metric contributes.</li>
                        <li><strong>Advantage:</strong> Direct auditability for security analysts during threat triage.</li>
                    </ul>
                </div>
                """
            ),
            unsafe_allow_html=True,
        )


def render_error_analysis_page(df_test_preds: Optional[pd.DataFrame], df_raw: pd.DataFrame, split_info: Optional[Dict[str, Any]], feat_cols: list):
    st.markdown('<div class="main-title">Model Error Analysis & Failure Cases</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">Deep dive into False Positives, False Negatives, and edge-case PE binaries</div>', unsafe_allow_html=True)

    if df_test_preds is None or df_test_preds.empty:
        st.error("⚠️ Test predictions not found at `models/test_predictions.csv`.")
        return

    # Error Types Breakdown
    df_merged = df_test_preds.copy()
    df_merged["Error_Type"] = "Correct"
    df_merged.loc[(df_merged["actual"] == 0) & (df_merged["predicted"] == 1), "Error_Type"] = "False Positive (FP)"
    df_merged.loc[(df_merged["actual"] == 1) & (df_merged["predicted"] == 0), "Error_Type"] = "False Negative (FN)"

    fp_df = df_merged[df_merged["Error_Type"] == "False Positive (FP)"]
    fn_df = df_merged[df_merged["Error_Type"] == "False Negative (FN)"]

    e1, e2, e3, e4 = st.columns(4)
    e1.metric("Total Test Samples", f"{len(df_merged):,}")
    e2.metric("Total Misclassified", f"{len(fp_df) + len(fn_df):,}", f"{(len(fp_df) + len(fn_df))/len(df_merged)*100:.2f}% Error Rate")
    e3.metric("False Positives (Benign -> Malware)", f"{len(fp_df):,}", "Type I Error")
    e4.metric("False Negatives (Malware -> Benign)", f"{len(fn_df):,}", "Type II Error (High Risk)", delta_color="inverse")

    st.divider()

    tab_fp, tab_fn, tab_all_err = st.tabs(["⚠️ False Positives (FP)", "🚨 False Negatives (FN)", "📋 All Misclassifications"])

    # Load raw feature values for context
    key_inspect_cols = ["TimeDateStamp", "Characteristics", "MajorLinkerVersion", "SizeOfCode", "SectionMaxEntropy", "CheckSum"]
    valid_inspect = [c for c in key_inspect_cols if c in df_raw.columns]

    with tab_fp:
        st.subheader(f"False Positives ({len(fp_df)} samples)")
        st.caption("Benign executables incorrectly classified as Malware. In enterprise deployment, high FP rates trigger false alert fatigue.")
        if not fp_df.empty:
            fp_indices = fp_df["original_index"].values
            fp_details = df_raw.loc[fp_indices, valid_inspect].copy()
            fp_details["Malware_Prob"] = fp_df["malware_probability"].values
            st.dataframe(fp_details, use_container_width=True)

    with tab_fn:
        st.subheader(f"False Negatives ({len(fn_df)} samples)")
        st.caption("Malware samples that evaded detection (classified as Benign). Represents the most critical security failure mode.")
        if not fn_df.empty:
            fn_indices = fn_df["original_index"].values
            fn_details = df_raw.loc[fn_indices, valid_inspect].copy()
            fn_details["Malware_Prob"] = fn_df["malware_probability"].values
            st.dataframe(fn_details, use_container_width=True)

    with tab_all_err:
        st.subheader("All Misclassified Test Rows")
        err_df = df_merged[df_merged["Error_Type"] != "Correct"]
        st.dataframe(err_df, use_container_width=True)