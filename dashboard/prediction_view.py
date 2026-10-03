"""
Malware Prediction View: Single Sample Inference & Batch CSV Processing.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional

import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st

COLOR_MALWARE = "#EF4444"
COLOR_BENIGN = "#3B82F6"


def render_prediction_page(model, feature_columns: List[str], df_raw: pd.DataFrame, split_info: Optional[Dict[str, Any]]):
    st.markdown('<div class="main-title">Malware Detection & Inference Engine</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">Live single PE header predictor & high-throughput batch CSV classification</div>', unsafe_allow_html=True)

    # Mandatory Security Warning Callout
    st.error(
        "⚠️ **SECURITY DISCLAIMER:** This is an ML prediction, not a security guarantee. "
        "Never execute uploaded files; only process tabular feature data extracted from static PE headers."
    )

    if model is None:
        st.error("❌ Final model artifact not found. Please train models first using `train_model.py`.")
        return

    tab_single, tab_batch = st.tabs(["🔍 Single Sample Inference", "📁 Batch CSV Processing"])

    # ==========================================
    # TAB 1: SINGLE SAMPLE PREDICTION
    # ==========================================
    with tab_single:
        st.subheader("1. Single Sample PE Header Predictor")
        st.write("Customize static PE feature values below or load values from a known sample.")

        # Preset Loader Controls
        c_load1, c_load2 = st.columns([1, 1])
        with c_load1:
            load_mode = st.radio("Preload Input Values With:", ["Training Dataset Medians", "Random Test Set Sample"], horizontal=True)
        with c_load2:
            if load_mode == "Random Test Set Sample" and split_info:
                test_indices = split_info.get("test_indices", [])
                if st.button("🎲 Pick New Random Test Row"):
                    st.session_state["rand_sample_idx"] = int(np.random.choice(test_indices))
            
        # Determine baseline values
        if load_mode == "Random Test Set Sample" and split_info:
            if "rand_sample_idx" not in st.session_state:
                st.session_state["rand_sample_idx"] = split_info["test_indices"][0]
            curr_idx = st.session_state["rand_sample_idx"]
            base_series = df_raw.loc[curr_idx, feature_columns]
            actual_label = "Malware (1)" if df_raw.loc[curr_idx, "Malware"] == 1 else "Benign (0)"
            st.caption(f"Loaded Row Index `{curr_idx}` (Ground Truth Label: **{actual_label}**)")
        else:
            base_series = df_raw[feature_columns].median()
            st.caption("Loaded median values across all 19,611 training records.")

        # Create input form with expandable sections for the 77 features
        with st.form("single_prediction_form"):
            st.markdown("#### Primary PE Structural Features (Editable)")
            
            # Highlight top 12 features in main grid
            top_features_preview = [
                "TimeDateStamp", "Characteristics", "MajorLinkerVersion", "MinorLinkerVersion",
                "SizeOfCode", "SizeOfImage", "SizeOfInitializedData", "ImageBase",
                "MajorOperatingSystemVersion", "MinorOperatingSystemVersion", "CheckSum", "Subsystem",
                "DllCharacteristics", "SizeOfStackReserve", "NumberOfSections", "SectionMaxEntropy"
            ]
            valid_top = [f for f in top_features_preview if f in feature_columns]
            other_features = [f for f in feature_columns if f not in valid_top]

            input_values = {}
            
            # Render Top Features in 4 columns
            cols = st.columns(4)
            for i, feat in enumerate(valid_top):
                with cols[i % 4]:
                    val = float(base_series.get(feat, 0.0))
                    input_values[feat] = st.number_input(
                        label=feat,
                        value=val,
                        key=f"input_{feat}",
                    )

            # Collapsible Expander for Remaining Features
            with st.expander(f"➕ Advanced PE Fields ({len(other_features)} additional headers)"):
                other_cols = st.columns(4)
                for i, feat in enumerate(other_features):
                    with other_cols[i % 4]:
                        val = float(base_series.get(feat, 0.0))
                        input_values[feat] = st.number_input(
                            label=feat,
                            value=val,
                            key=f"input_{feat}",
                        )

            submit_btn = st.form_submit_button("🛡️ Predict Malware Probability", type="primary")

        if submit_btn:
            # Construct DataFrame with exact column order from feature_columns.json
            input_df = pd.DataFrame([[input_values[col] for col in feature_columns]], columns=feature_columns)

            # Pass directly into the fitted pipeline (never reordering manually)
            pred_class = int(model.predict(input_df)[0])
            prob_dist = model.predict_proba(input_df)[0]
            prob_benign = float(prob_dist[0])
            prob_malware = float(prob_dist[1])
            confidence = float(max(prob_benign, prob_malware))

            st.markdown("<br>", unsafe_allow_html=True)
            st.subheader("🎯 Prediction Result")

            r1, r2, r3, r4 = st.columns(4)
            with r1:
                if pred_class == 1:
                    st.markdown(
                        f"""
                        <div class="kpi-card" style="border: 2px solid {COLOR_MALWARE};">
                            <div class="kpi-value" style="color: {COLOR_MALWARE};">MALWARE</div>
                            <div class="kpi-label">Class 1 Detected</div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                else:
                    st.markdown(
                        f"""
                        <div class="kpi-card" style="border: 2px solid {COLOR_BENIGN};">
                            <div class="kpi-value" style="color: {COLOR_BENIGN};">BENIGN</div>
                            <div class="kpi-label">Class 0 Clean</div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

            with r2:
                st.metric("Malware Probability", f"{prob_malware * 100:.2f}%")
            with r3:
                st.metric("Benign Probability", f"{prob_benign * 100:.2f}%")
            with r4:
                st.metric("Model Confidence", f"{confidence * 100:.2f}%")

            # Probability Gauge / Bar
            prob_df = pd.DataFrame({
                "Class": ["Benign", "Malware"],
                "Probability": [prob_benign, prob_malware],
            })
            fig_prob = px.bar(
                prob_df,
                x="Probability",
                y="Class",
                orientation="h",
                text_auto=".2%",
                color="Class",
                color_discrete_map={"Benign": COLOR_BENIGN, "Malware": COLOR_MALWARE},
                title="Classification Probability Distribution",
                height=220,
            )
            fig_prob.update_xaxes(range=[0, 1])
            st.plotly_chart(fig_prob, use_container_width=True)

    # ==========================================
    # TAB 2: BATCH CSV PROCESSING
    # ==========================================
    with tab_batch:
        st.subheader("2. Batch PE Features CSV Processing")
        st.write("Upload a CSV file containing extracted PE header feature rows.")

        uploaded_file = st.file_uploader(
            "Upload Feature CSV file (Max 20MB):",
            type=["csv"],
            help="Must contain all 77 numeric PE features. Extra columns will be safely ignored.",
        )

        if uploaded_file is not None:
            try:
                batch_df = pd.read_csv(uploaded_file)
                st.write(f"📁 Loaded CSV containing `{len(batch_df):,}` rows and `{len(batch_df.columns):,}` columns.")

                # Validation 1: Check for missing required columns
                uploaded_cols = set(batch_df.columns)
                required_cols = set(feature_columns)
                missing_cols = list(required_cols - uploaded_cols)
                extra_cols = list(uploaded_cols - required_cols)

                if missing_cols:
                    st.error(
                        f"❌ **Validation Failed:** The uploaded CSV is missing **{len(missing_cols)}** required feature columns:\n"
                        f"`{missing_cols}`\n\n"
                        "Please ensure all 77 PE header features are present in the upload."
                    )
                else:
                    if extra_cols:
                        st.warning(f"⚠️ **Notice:** Found {len(extra_cols)} non-standard columns (e.g. identifiers or targets). These will be ignored during inference.")

                    # Validation 2: Check for NaN / Non-numeric values in required columns
                    feature_subset = batch_df[feature_columns].copy()
                    
                    non_numeric_cols = []
                    for col in feature_columns:
                        if not pd.api.types.is_numeric_dtype(feature_subset[col]):
                            try:
                                feature_subset[col] = pd.to_numeric(feature_subset[col])
                            except Exception:
                                non_numeric_cols.append(col)

                    if non_numeric_cols:
                        st.error(f"❌ **Data Type Error:** Non-numeric values detected in columns: `{non_numeric_cols}`. All feature columns must contain numeric values.")
                    elif feature_subset.isnull().sum().sum() > 0:
                        null_counts = feature_subset.isnull().sum()
                        null_cols = null_counts[null_counts > 0].to_dict()
                        st.error(f"❌ **Missing Values Error:** Uploaded batch contains NaN/null values: `{null_cols}`. Please clean or impute the file before prediction.")
                    else:
                        st.success("✅ **Validation Passed:** All 77 required features validated successfully!")

                        if st.button("⚡ Run Batch Classification", type="primary"):
                            with st.spinner(f"Predicting labels for {len(feature_subset):,} samples..."):
                                # Run pipeline directly on feature subset
                                batch_preds = model.predict(feature_subset)
                                batch_probs = model.predict_proba(feature_subset)

                                results_df = batch_df.copy()
                                results_df["Predicted_Label"] = ["MALWARE" if p == 1 else "BENIGN" for p in batch_preds]
                                results_df["Malware_Probability"] = batch_probs[:, 1].round(4)
                                results_df["Benign_Probability"] = batch_probs[:, 0].round(4)
                                results_df["Confidence"] = np.max(batch_probs, axis=1).round(4)

                                # Save in session state for downloads page
                                st.session_state["batch_predictions_df"] = results_df

                                # Batch KPIs
                                mal_count = int(np.sum(batch_preds == 1))
                                ben_count = int(np.sum(batch_preds == 0))
                                total_count = len(batch_preds)

                                st.markdown("<br>", unsafe_allow_html=True)
                                st.subheader("📊 Batch Inference Summary")
                                b1, b2, b3, b4 = st.columns(4)
                                b1.metric("Total Executables", f"{total_count:,}")
                                b2.metric("Predicted Malware", f"{mal_count:,}", f"{mal_count/total_count*100:.1f}%", delta_color="inverse")
                                b3.metric("Predicted Benign", f"{ben_count:,}", f"{ben_count/total_count*100:.1f}%")
                                b4.metric("Avg Confidence", f"{results_df['Confidence'].mean()*100:.2f}%")

                                # Batch Donut
                                fig_batch = px.pie(
                                    values=[ben_count, mal_count],
                                    names=["BENIGN", "MALWARE"],
                                    hole=0.45,
                                    color=["BENIGN", "MALWARE"],
                                    color_discrete_map={"BENIGN": COLOR_BENIGN, "MALWARE": COLOR_MALWARE},
                                    title="Batch Detection Breakdown",
                                    height=320,
                                )
                                st.plotly_chart(fig_batch, use_container_width=True)

                                # Preview of annotated batch
                                st.subheader("Batch Predictions Preview")
                                display_cols = ["Predicted_Label", "Malware_Probability", "Benign_Probability", "Confidence"] + feature_columns[:5]
                                if "Hash_md5_Name" in results_df.columns:
                                    display_cols = ["Hash_md5_Name"] + display_cols
                                st.dataframe(results_df[display_cols].head(50), use_container_width=True)

                                # Download Button
                                csv_data = results_df.to_csv(index=False).encode("utf-8")
                                st.download_button(
                                    label="📥 Download batch_predictions.csv",
                                    data=csv_data,
                                    file_name="batch_predictions.csv",
                                    mime="text/csv",
                                )

            except Exception as e:
                st.error(f"❌ Error processing batch file: {e}")