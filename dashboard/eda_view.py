"""EDA Tab Renderers for Dashboard."""
import pandas as pd
import plotly.express as px
import streamlit as st

COLOR_MALWARE = "#EF4444"
COLOR_BENIGN = "#3B82F6"

def render_target_tab(summary):
    st.subheader("Class Balance Analysis")
    c1, c2 = st.columns(2)
    target_df = pd.DataFrame({
        "Class": ["Benign (0)", "Malware (1)"],
        "Count": [summary["benign_count"], summary["malware_count"]],
        "Percentage": [summary["benign_percentage"], summary["malware_percentage"]],
    })
    with c1:
        fig_bar = px.bar(
            target_df, x="Class", y="Count", color="Class", text="Count",
            color_discrete_map={"Benign (0)": COLOR_BENIGN, "Malware (1)": COLOR_MALWARE},
            title="Target Class Sample Counts", height=380,
        )
        fig_bar.update_traces(texttemplate="%{text:,}", textposition="outside")
        st.plotly_chart(fig_bar, use_container_width=True)
    with c2:
        fig_donut = px.pie(
            target_df, names="Class", values="Count", hole=0.5, color="Class",
            color_discrete_map={"Benign (0)": COLOR_BENIGN, "Malware (1)": COLOR_MALWARE},
            title="Target Class Proportions", height=380,
        )
        fig_donut.update_traces(textinfo="label+percent")
        st.plotly_chart(fig_donut, use_container_width=True)
    st.info("💡 **Imbalance Observation:** The dataset exhibits a **~74.4% Malware to ~25.6% Benign** distribution (~3:1 ratio). All machine learning models utilize `class_weight='balanced'` and Stratified K-Fold CV to prevent majority class bias.")

def render_histograms_tab(df, feat_cols):
    st.subheader("Feature Distribution Histograms")
    defaults = ["SizeOfCode", "SizeOfImage", "NumberOfSections", "SectionMaxEntropy", "SectionMinEntropy", "SuspiciousImportFunctions"]
    valid_defaults = [f for f in defaults if f in feat_cols]
    selected_feat = st.selectbox("Select feature to visualize distribution:", options=feat_cols, index=feat_cols.index(valid_defaults[0]) if valid_defaults else 0)
    use_log = st.checkbox("Log scale (Y-axis)", value=True)
    fig_hist = px.histogram(
        df, x=selected_feat, color=df["Malware"].map({0: "Benign", 1: "Malware"}),
        barmode="overlay", opacity=0.7, log_y=use_log,
        color_discrete_map={"Benign": COLOR_BENIGN, "Malware": COLOR_MALWARE},
        title=f"Distribution of '{selected_feat}' by Class", height=450,
    )
    st.plotly_chart(fig_hist, use_container_width=True)

def render_boxplots_tab(df, feat_cols):
    st.subheader("Box Plots & PE Outlier Analysis")
    st.warning("📌 **Domain Note on Outliers:** PE file attributes naturally exhibit extreme outliers (e.g. packed binaries with very large section sizes or anomalous resource segments). These outliers are shown for domain analysis and PE structural inspection; they are retained to capture genuine anomalous executable signatures.")
    selected_box = st.selectbox("Select feature for box plot:", options=feat_cols, index=feat_cols.index("SectionMaxEntropy") if "SectionMaxEntropy" in feat_cols else 0, key="box_select")
    df_box = df[[selected_box, "Malware"]].copy()
    df_box["Class"] = df_box["Malware"].map({0: "Benign", 1: "Malware"})
    fig_box = px.box(
        df_box, x="Class", y=selected_box, color="Class", points="outliers",
        color_discrete_map={"Benign": COLOR_BENIGN, "Malware": COLOR_MALWARE},
        title=f"Box Plot: '{selected_box}' by Class", height=450,
    )
    st.plotly_chart(fig_box, use_container_width=True)

def render_correlation_tab(df, feat_cols):
    st.subheader("Pairwise Feature Correlation Heatmap")
    st.caption("Select a subset of features (5 to 15 recommended) to inspect collinearity. Note: To prevent UI freeze, correlation is computed dynamically on your selection.")
    defaults = ["SizeOfCode", "SizeOfImage", "SizeOfInitializedData", "NumberOfSections", "SectionMaxEntropy", "SectionMinEntropy", "TimeDateStamp", "MajorLinkerVersion", "SuspiciousImportFunctions"]
    valid_defaults = [f for f in defaults if f in feat_cols]
    selected_corr = st.multiselect("Select features for Correlation Heatmap:", options=feat_cols, default=valid_defaults, max_selections=20)
    if len(selected_corr) < 2:
        st.info("Please select at least 2 features to render the correlation heatmap.")
    else:
        corr_matrix = df[selected_corr].corr()
        fig_heat = px.imshow(corr_matrix, text_auto=".2f", color_continuous_scale="RdBu_r", zmin=-1, zmax=1, title=f"Correlation Matrix ({len(selected_corr)} Selected Features)", height=550)
        st.plotly_chart(fig_heat, use_container_width=True)

def render_scatter_tab(df, feat_cols):
    st.subheader("2D Feature Separability Scatter Plot")
    st.caption("Interactive 2D projection colored by class label (subsampled up to 5,000 points for responsiveness).")
    c1, c2, c3 = st.columns(3)
    with c1:
        fx = st.selectbox("X-Axis Feature:", options=feat_cols, index=feat_cols.index("SizeOfCode") if "SizeOfCode" in feat_cols else 0)
    with c2:
        fy = st.selectbox("Y-Axis Feature:", options=feat_cols, index=feat_cols.index("SectionMaxEntropy") if "SectionMaxEntropy" in feat_cols else 1)
    with c3:
        sample_size = st.slider("Max Sample Points:", min_value=1000, max_value=5000, value=3000, step=500)
    df_sample = df.sample(n=min(sample_size, len(df)), random_state=42).copy()
    df_sample["Class"] = df_sample["Malware"].map({0: "Benign", 1: "Malware"})
    fig_scatter = px.scatter(
        df_sample, x=fx, y=fy, color="Class", opacity=0.6,
        color_discrete_map={"Benign": COLOR_BENIGN, "Malware": COLOR_MALWARE},
        title=f"Scatter: {fx} vs. {fy}", height=500,
    )
    st.plotly_chart(fig_scatter, use_container_width=True)

def render_comparison_tab(df, feat_cols):
    st.subheader("Class-Wise Statistical Comparison Table")
    st.caption("Compare mean, median, and standard deviation across Benign vs. Malware files.")
    comp_features = st.multiselect("Select features to compare:", options=feat_cols, default=feat_cols[:10])
    if comp_features:
        comp_data = []
        for f in comp_features:
            b_vals = df[df["Malware"] == 0][f]
            m_vals = df[df["Malware"] == 1][f]
            comp_data.append({
                "Feature": f,
                "Benign Mean": b_vals.mean(),
                "Malware Mean": m_vals.mean(),
                "Benign Median": b_vals.median(),
                "Malware Median": m_vals.median(),
                "Benign Std": b_vals.std(),
                "Malware Std": m_vals.std(),
            })
        df_comp = pd.DataFrame(comp_data)
        st.dataframe(df_comp.style.format("{:.2f}", subset=df_comp.columns[1:]), use_container_width=True)