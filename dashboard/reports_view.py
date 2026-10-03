"""
Batch Analysis, Artifact Export, and About Project Views.
"""

import json
import textwrap
from pathlib import Path
from typing import Dict, Any, List, Optional

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

COLOR_MALWARE = "#EF4444"
COLOR_BENIGN = "#10B981"


def render_batch_analysis_page(
    model,
    feature_columns: List[str],
    project_root: Path,
):
    st.markdown('<div class="main-title">Batch Feature Classification & Artifacts</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">High-throughput tabular PE feature prediction, batch CSV export, and model artifact downloads</div>', unsafe_allow_html=True)

    tab_batch, tab_artifacts, tab_plots = st.tabs([
        "📁 Batch CSV Classification",
        "📊 System Reports & Models",
        "🖼️ Generated Visualizations",
    ])

    # ==========================================
    # TAB 1: BATCH CSV INFERENCE
    # ==========================================
    with tab_batch:
        st.subheader("1. Tabular PE Feature Batch Classification")
        st.caption("Upload a CSV file containing rows of PE header features (matching the 77 features in `feature_columns.json`).")
        st.info("ℹ️ **Safety Note:** This module processes static tabular numeric data only. It never executes binary code.")

        # Template CSV Download for Testing
        sample_path = project_root / "data" / "Malware-Benign.csv"
        if sample_path.exists():
            try:
                sample_df = pd.read_csv(sample_path, nrows=50)
                csv_cols = [c for c in feature_columns if c in sample_df.columns]
                template_csv = sample_df[csv_cols].to_csv(index=False).encode("utf-8")
                st.download_button(
                    label="📥 Download Sample Feature CSV (50 Rows)",
                    data=template_csv,
                    file_name="sample_pe_features_batch.csv",
                    mime="text/csv",
                    help="Use this template CSV to test batch classification.",
                )
            except Exception:
                pass

        uploaded_batch = st.file_uploader(
            "Upload Batch PE Features CSV",
            type=["csv"],
            help="Upload a CSV with all 77 required PE feature columns.",
        )

        if uploaded_batch is not None:
            try:
                batch_df = pd.read_csv(uploaded_batch)
                st.write(f"📁 **Uploaded CSV:** `{uploaded_batch.name}` ({len(batch_df):,} rows, {len(batch_df.columns)} columns)")

                # Validate feature columns
                missing_cols = [col for col in feature_columns if col not in batch_df.columns]
                
                if missing_cols:
                    st.error(f"❌ Batch validation failed: CSV is missing {len(missing_cols)} required feature column(s).")
                    with st.expander("View Missing Columns"):
                        st.write(missing_cols)
                else:
                    st.success(f"✅ Schema validation passed! All {len(feature_columns)} expected feature columns are present.")
                    
                    if model is None:
                        st.error("❌ Final model artifact not found. Please train models first using `train_model.py`.")
                    else:
                        if st.button("🚀 Run Batch Classification", type="primary", use_container_width=True):
                            batch_loader = st.empty()
                            batch_loader.markdown(
                                f"""
                                <div style="display: flex; align-items: center; gap: 12px; background: rgba(19, 28, 46, 0.85); border: 1px solid rgba(0, 210, 255, 0.35); border-radius: 10px; padding: 12px 18px; margin: 12px 0;">
                                    <span class="step-spinner"></span>
                                    <span style="color: #00D2FF; font-weight: 600; font-size: 0.95rem;">⚡ Scanning tabular PE feature vectors & executing model inference ({len(batch_df):,} records)...</span>
                                </div>
                                """,
                                unsafe_allow_html=True,
                            )
                            # Ensure exact column ordering
                            X_input = batch_df[feature_columns].copy()
                            
                            # Coerce to numeric
                            X_input = X_input.apply(pd.to_numeric, errors="coerce").fillna(0.0)

                            probs = model.predict_proba(X_input)
                            p_benign = probs[:, 0]
                            p_malware = probs[:, 1]
                            preds = (p_malware >= 0.5).astype(int)

                            results_df = batch_df.copy()
                            results_df["Predicted_Class"] = preds
                            results_df["Probability_Malware"] = np.round(p_malware, 4)
                            results_df["Probability_Benign"] = np.round(p_benign, 4)
                            results_df["Verdict"] = np.where(preds == 1, "Potential Malware", "Likely Benign")

                            batch_loader.empty()

                            total_count = len(results_df)
                            malware_count = int(np.sum(preds == 1))
                            benign_count = total_count - malware_count

                            st.session_state["last_batch_results"] = results_df

                        # If results are ready in session state
                        if "last_batch_results" in st.session_state:
                            res_df = st.session_state["last_batch_results"]
                            tot = len(res_df)
                            mal_cnt = int(np.sum(res_df["Predicted_Class"] == 1))
                            ben_cnt = tot - mal_cnt

                            st.markdown("---")
                            st.markdown("### 📊 Batch Classification Summary")

                            b1, b2, b3 = st.columns(3)
                            b1.metric("Total Rows Evaluated", f"{tot:,}")
                            b2.metric("Predicted Malware", f"{mal_cnt:,} ({mal_cnt/tot*100:.1f}%)")
                            b3.metric("Predicted Benign", f"{ben_cnt:,} ({ben_cnt/tot*100:.1f}%)")

                            # Summary Bar Chart
                            chart_df = pd.DataFrame({
                                "Classification": ["Likely Benign", "Potential Malware"],
                                "Count": [ben_cnt, mal_cnt],
                                "Percentage": [ben_cnt/tot*100, mal_cnt/tot*100],
                            })
                            fig_summary = px.bar(
                                chart_df,
                                x="Classification",
                                y="Count",
                                text="Count",
                                color="Classification",
                                color_discrete_map={"Likely Benign": COLOR_BENIGN, "Potential Malware": COLOR_MALWARE},
                                title="Batch Prediction Class Distribution",
                            )
                            fig_summary.update_layout(
                                template="plotly_dark",
                                paper_bgcolor="rgba(0,0,0,0)",
                                plot_bgcolor="rgba(0,0,0,0)",
                                height=300,
                            )
                            st.plotly_chart(fig_summary, use_container_width=True)

                            st.markdown("#### Predictions Table Preview")
                            st.dataframe(res_df[["Verdict", "Probability_Malware", "Probability_Benign"] + [c for c in res_df.columns if c not in ["Verdict", "Probability_Malware", "Probability_Benign", "Predicted_Class"]][:100]], use_container_width=True)

                            st.download_button(
                                label=f"📥 Download Complete Batch Predictions CSV ({len(res_df):,} Rows)",
                                data=res_df.to_csv(index=False).encode("utf-8"),
                                file_name="batch_predictions_classified.csv",
                                mime="text/csv",
                            )

            except Exception as e:
                st.error(f"❌ Error processing batch CSV: {e}")

    # ==========================================
    # TAB 2: SYSTEM REPORTS & MODEL DOWNLOADS
    # ==========================================
    with tab_artifacts:
        st.subheader("2. Metric Tables & Classification Reports")
        
        c1, c2 = st.columns(2)
        with c1:
            # Model Comparison Report
            rep_path = project_root / "outputs" / "reports" / "model_comparison_report.csv"
            if rep_path.exists():
                with open(rep_path, "rb") as f:
                    st.download_button(
                        label="📥 Download model_comparison_report.csv",
                        data=f.read(),
                        file_name="model_comparison_report.csv",
                        mime="text/csv",
                    )
            else:
                st.warning("model_comparison_report.csv not generated yet.")

            # Feature Importance Report
            imp_path = project_root / "models" / "feature_importance.csv"
            if imp_path.exists():
                with open(imp_path, "rb") as f:
                    st.download_button(
                        label="📥 Download feature_importance.csv",
                        data=f.read(),
                        file_name="feature_importance.csv",
                        mime="text/csv",
                    )
            else:
                st.warning("feature_importance.csv not found.")

        with c2:
            # Classification Reports JSON
            cls_path = project_root / "outputs" / "reports" / "classification_reports.json"
            if cls_path.exists():
                with open(cls_path, "rb") as f:
                    st.download_button(
                        label="📥 Download classification_reports.json",
                        data=f.read(),
                        file_name="classification_reports.json",
                        mime="application/json",
                    )
            else:
                st.warning("classification_reports.json not found.")

            # Selected Features JSON
            sel_path = project_root / "models" / "selected_features.json"
            if sel_path.exists():
                with open(sel_path, "rb") as f:
                    st.download_button(
                        label="📥 Download selected_features.json",
                        data=f.read(),
                        file_name="selected_features.json",
                        mime="application/json",
                    )
            else:
                st.warning("selected_features.json not found.")

    # ==========================================
    # TAB 3: HIGH-RESOLUTION VISUALIZATIONS
    # ==========================================
    with tab_plots:
        st.subheader("3. High-Resolution Visualizations (PNG)")
        p_col1, p_col2 = st.columns(2)

        with p_col1:
            cm_plot = project_root / "outputs" / "confusion_matrix" / "confusion_matrices_all.png"
            if cm_plot.exists():
                with open(cm_plot, "rb") as f:
                    st.download_button(
                        label="🖼️ Download Confusion Matrices (PNG)",
                        data=f.read(),
                        file_name="confusion_matrices_all.png",
                        mime="image/png",
                    )
                st.image(str(cm_plot), caption="Confusion Matrices Comparison")

            roc_plot = project_root / "outputs" / "roc_curves" / "roc_curves_all.png"
            if roc_plot.exists():
                with open(roc_plot, "rb") as f:
                    st.download_button(
                        label="🖼️ Download ROC Curves (PNG)",
                        data=f.read(),
                        file_name="roc_curves_all.png",
                        mime="image/png",
                    )
                st.image(str(roc_plot), caption="ROC Curves Comparison")

        with p_col2:
            pr_plot = project_root / "outputs" / "roc_curves" / "pr_curves_all.png"
            if pr_plot.exists():
                with open(pr_plot, "rb") as f:
                    st.download_button(
                        label="🖼️ Download PR Curves (PNG)",
                        data=f.read(),
                        file_name="pr_curves_all.png",
                        mime="image/png",
                    )
                st.image(str(pr_plot), caption="Precision-Recall Curves Comparison")

            top_plot = project_root / "outputs" / "feature_importance" / "top_features.png"
            if top_plot.exists():
                with open(top_plot, "rb") as f:
                    st.download_button(
                        label="🖼️ Download Top Features (PNG)",
                        data=f.read(),
                        file_name="top_features.png",
                        mime="image/png",
                    )
                st.image(str(top_plot), caption="Top Feature Importances")


def render_about_project_page():
    st.markdown('<div class="main-title">About the Project</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">System documentation, dataset architecture, methodology, and limitations</div>', unsafe_allow_html=True)

    st.subheader("🎯 Project Purpose & Scope")
    st.info(
        "**Malware Sentinel** is an automated static machine-learning system designed to detect Windows Portable Executable (PE) "
        "malware threats directly from header metadata and structural section properties without requiring dangerous live sandbox execution."
    )

    st.subheader("📊 Dataset Description")
    st.markdown(
        textwrap.dedent(
            """
            - **Data Source:** Portable Executable static metadata (`Malware-Benign.csv`).
            - **Sample Count:** **19,611** Windows executable binaries (**14,599** Malware [74.4%], **5,012** Benign [25.6%]).
            - **Feature Space:** **77** raw numeric metrics spanning DOS headers, File/COFF headers, Optional headers, Section tables, and Data Directories.
            - **Integrity:** Zero missing values across all records; verified unique MD5 hash identification.
            - **Partitioning:** Stratified 80/20 train/test split (15,688 training samples / 3,923 out-of-sample test samples).
            """
        )
    )

    st.subheader("⚙️ Machine Learning Pipeline Summary")
    st.markdown(
        textwrap.dedent(
            """
            1. **Domain Feature Engineering (`FeatureEngineer`):** 5 domain ratio and section entropy spread indicators with safe division.
            2. **Constant Feature Pruning (`VarianceThreshold`):** Removal of zero-variance constant features across the training set.
            3. **Collinearity Filter (`CorrelationFilter`):** Deterministic elimination of redundant features with $|r| > 0.95$.
            4. **Tree-Based Feature Selection (`SelectFromModel`):** Selection of top predictive features using Random Forest importance.
            5. **Classification & Cross-Validation:** 5-fold Stratified Cross-Validation on the training partition; model selection based on CV F1 score.
            6. **Model Interpretability:** Global feature importance ranking and sample-level local SHAP attributions.
            """
        )
    )

    st.subheader("⚠️ Limitations & Security Disclaimer")
    st.markdown(
        textwrap.dedent(
            """
            - **Static Inspection Only:** The model evaluates PE header structural metadata. It does not observe dynamic execution behavior (e.g. API call sequences, process injection, registry tampering, network traffic).
            - **Probabilistic Predictions:** All outputs are probabilistic likelihood scores based on statistical patterns in the training corpus; they are not deterministic guarantees.
            - **Heuristic Reconstructions:** Certain dataset features (e.g. `SuspiciousImportFunctions`, `SuspiciousNameSection`) are reconstructed approximations from static exports/imports and should be treated with appropriate caution.
            - **Adversarial & Evasion Risks:** Sophisticated threat actors utilizing custom packers, crypters, or header spoofing may evade static feature classifiers.
            - **Defense-in-Depth:** This system is intended as a high-speed pre-filtering stage and is **not a replacement for dynamic sandboxing, signature scanners, or enterprise Endpoint Detection & Response (EDR) solutions**.
            """
        )
    )

    st.divider()
    st.caption("🛡️ Malware Sentinel • AI-Powered Static PE Analysis Platform • Version 2.0")