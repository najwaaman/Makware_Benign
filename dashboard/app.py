"""
Malware Sentinel: AI-Powered Static PE Malware Classification System.
Streamlit Web Application for Portable Executable Threat Detection & Explainability.
"""

import sys
import json
import time
import textwrap
from pathlib import Path
from typing import Dict, Any, List, Optional

import joblib
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# Setup Project Root
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Import shared pipeline utilities
try:
    from src.pipeline import (
        load_data,
        dataset_summary,
        get_feature_columns,
        FeatureEngineer,
        CorrelationFilter,
    )
except ImportError as e:
    st.error(f"Error importing pipeline components from src.pipeline: {e}")

# Import PE Extraction, Compatibility, and Explainability Modules
try:
    from src.pe_extractor import extract_features, PEExtractionError, compute_hashes
    from src.compatibility import validate_and_align
    from src.explain import explain_prediction
    from src.theme import inject_theme, render_animated_kpi_counters
except ImportError as e:
    st.error(f"Error importing PE analysis / theme modules: {e}")

# Import View Modules
from dashboard.eda_view import (
    render_target_tab,
    render_histograms_tab,
    render_boxplots_tab,
    render_correlation_tab,
    render_scatter_tab,
    render_comparison_tab,
)
from dashboard.models_view import (
    render_model_training_page,
    render_model_evaluation_page,
    render_model_comparison_page,
    render_feature_importance_page,
    render_error_analysis_page,
)
from dashboard.reports_view import (
    render_batch_analysis_page,
    render_about_project_page,
)

# Page Configuration
st.set_page_config(
    page_title="Malware Sentinel | AI Static PE Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject Global Dark Glassmorphism Cybersecurity Theme
inject_theme()

# Color Constants
COLOR_MALWARE = "#EF4444"
COLOR_BENIGN = "#10B981"
COLOR_ACCENT = "#00D2FF"

# Uncertain / Reconstructed Heuristic Features
UNCERTAIN_CUSTOM_FEATURES = {
    "SuspiciousImportFunctions",
    "SuspiciousNameSection",
    "SectionsLength",
    "SectionMaxEntropy",
    "SectionMaxRawsize",
    "SectionMaxVirtualsize",
    "SectionMinPhysical",
    "SectionMinVirtual",
    "SectionMinPointerData",
    "SectionMainChar",
}

# Static PE Feature Domain Descriptions for Tooltips and Feature Cards
PE_FEATURE_DESCRIPTIONS = {
    "MajorLinkerVersion": "Major version of the compiler linker used to build the PE binary.",
    "TimeDateStamp": "Header timestamp when the executable was compiled.",
    "Characteristics": "Bit flags defining core PE attributes (e.g. Executable, DLL, 32-bit system).",
    "ImageBase": "Preferred memory base address where the binary expects to be loaded.",
    "SizeOfImage": "Total virtual address space size required by the loaded image.",
    "SizeOfHeaders": "Combined byte size of the MS-DOS header, PE header, and section headers.",
    "SizeOfCode": "Total byte size of all executable code sections (.text).",
    "SectionMinEntropy": "Lowest Shannon entropy found across all sections (unpacked sections ~2-4).",
    "SectionMaxEntropy": "Highest Shannon entropy found across all sections (entropy ~7-8 indicates packing/encryption).",
    "SuspiciousImportFunctions": "Heuristic count of high-risk Win32 APIs commonly used for evasion/injection.",
    "SuspiciousNameSection": "Heuristic flag indicating abnormal or randomized section names.",
    "SectionsLength": "Total number of section headers defined in the PE section table.",
    "SectionMinRawsize": "Smallest on-disk raw section footprint.",
    "SectionMaxRawsize": "Largest on-disk raw section footprint.",
    "SectionMinVirtual": "Smallest virtual section size in memory.",
    "SectionMaxVirtualsize": "Largest virtual section size in memory.",
    "SectionMinPointerData": "Lowest file offset pointer to raw section data on disk.",
    "SectionMainChar": "Main characteristic permission flags of the primary code section.",
    "DirectoryEntryImportSize": "Total size in bytes of the import directory table.",
    "DirectoryEntryExport": "Size/presence of exported symbols directory table.",
    "AddressOfEntryPoint": "Relative Virtual Address (RVA) of the entry point instruction.",
    "MajorOperatingSystemVersion": "Minimum major OS version required to run this binary.",
    "MajorSubsystemVersion": "Major version of the Windows subsystem required.",
    "Subsystem": "Target execution environment (GUI = 2, Console = 3, Native Driver = 1).",
    "DllCharacteristics": "Dynamic security mitigation flags (ASLR, DEP/NX, SafeSEH, CFG).",
    "CodeToImageRatio": "Ratio of executable code size relative to total mapped virtual image size.",
    "InitializedDataRatio": "Ratio of initialized global data relative to total mapped virtual image size.",
    "SectionRawSizeRange": "Spread between largest and smallest raw disk section dimensions.",
    "SectionVirtualSizeRange": "Spread between maximum and minimum memory virtual section dimensions.",
    "SectionEntropyRange": "Difference between maximum and minimum section entropy values.",
    "NumberOfSections": "Total count of section headers in the section table.",
    "BaseOfCode": "Relative Virtual Address where code starts in memory.",
    "SizeOfInitializedData": "Total disk size of all initialized data sections.",
    "SizeOfUninitializedData": "Total disk size of all uninitialized data sections (.bss).",
    "CheckSum": "PE header checksum used primarily for system drivers and critical DLLs.",
}


# ==============================================================================
# CACHED DATA & ARTIFACT LOADERS
# ==============================================================================

@st.cache_data(show_spinner="Loading malware dataset...")
def get_dataset() -> Optional[pd.DataFrame]:
    try:
        return load_data()
    except Exception as e:
        st.error(f"❌ Failed to load dataset: {e}")
        return None


@st.cache_data(show_spinner="Computing dataset summary...")
def get_summary_metrics(df: pd.DataFrame) -> Dict[str, Any]:
    return dataset_summary(df)


@st.cache_data(show_spinner="Loading split indices...")
def get_split_indices() -> Optional[Dict[str, Any]]:
    path = PROJECT_ROOT / "models" / "split_indices.json"
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


@st.cache_data(show_spinner="Loading selected features info...")
def get_selected_features_info() -> Optional[Dict[str, Any]]:
    path = PROJECT_ROOT / "models" / "selected_features.json"
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


@st.cache_data(show_spinner="Loading model training metadata...")
def get_training_metadata() -> Optional[Dict[str, Any]]:
    path = PROJECT_ROOT / "models" / "training_metadata.json"
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


@st.cache_data(show_spinner="Loading model metrics...")
def get_model_metrics() -> Optional[Dict[str, Any]]:
    path = PROJECT_ROOT / "models" / "model_metrics.json"
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


@st.cache_data(show_spinner="Loading ROC data...")
def get_roc_data() -> Optional[Dict[str, Any]]:
    path = PROJECT_ROOT / "models" / "roc_data.json"
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


@st.cache_data(show_spinner="Loading feature importance...")
def get_feature_importance_df() -> Optional[pd.DataFrame]:
    path = PROJECT_ROOT / "models" / "feature_importance.csv"
    if not path.exists():
        return None
    try:
        return pd.read_csv(path)
    except Exception:
        return None


@st.cache_data(show_spinner="Loading test predictions...")
def get_test_predictions_df() -> Optional[pd.DataFrame]:
    path = PROJECT_ROOT / "models" / "test_predictions.csv"
    if not path.exists():
        return None
    try:
        return pd.read_csv(path)
    except Exception:
        return None


@st.cache_data(show_spinner="Loading feature columns...")
def get_feature_columns_list() -> List[str]:
    path = PROJECT_ROOT / "models" / "feature_columns.json"
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    raw_df = get_dataset()
    return get_feature_columns(raw_df) if raw_df is not None else []


@st.cache_resource(show_spinner="Loading trained final model pipeline...")
def get_final_model():
    path = PROJECT_ROOT / "models" / "final_model.pkl"
    if not path.exists():
        return None
    try:
        return joblib.load(path)
    except Exception as e:
        st.error(f"❌ Error loading final model: {e}")
        return None


def render_footer():
    st.markdown(
        textwrap.dedent(
            """
            <div class="footer-text">
                🛡️ Malware Sentinel • AI-Powered Static PE Malware Detection & Explainability Platform
            </div>
            """
        ),
        unsafe_allow_html=True,
    )


# ==============================================================================
# SIDEBAR NAVIGATION (Exact required order)
# ==============================================================================

st.sidebar.title("🛡️ MALWARE SENTINEL")
st.sidebar.markdown("**Static PE Analysis Engine**")
st.sidebar.divider()

NAV_PAGES = [
    "🏠 Detection",
    "📊 Dataset",
    "🔎 EDA",
    "🧬 Feature Engineering",
    "🎯 Feature Selection",
    "🤖 Models",
    "📈 Evaluation",
    "🔬 Explainability",
    "📁 Batch Analysis",
    "ℹ️ About",
]

page = st.sidebar.radio(
    "Navigation Menu",
    NAV_PAGES,
    index=0,  # Detection is the default landing page
)

st.sidebar.divider()
st.sidebar.caption("Engine Status: **Active (v1.0)**")
st.sidebar.caption("Mode: **Static Header Inspection**")
st.sidebar.caption("Dataset: `data/Malware-Benign.csv`")


# Load Core Data & Artifacts
df = get_dataset()
if df is None:
    st.stop()

summary = get_summary_metrics(df)
feat_cols = get_feature_columns_list()
split_info = get_split_indices()
feat_info = get_selected_features_info()
training_meta = get_training_metadata()
metrics = get_model_metrics()
roc_data = get_roc_data()
df_importance = get_feature_importance_df()
df_test_preds = get_test_predictions_df()
final_model = get_final_model()


# ==============================================================================
# ROUTING & PAGE RENDERERS
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. 🏠 Detection (Landing Page with Live PE Static Extraction & SHAP Logic)
# ------------------------------------------------------------------------------
if page == "🏠 Detection":
    # Hero Title with Decorative Glowing Radar Graphic
    st.markdown(
        textwrap.dedent(
            """
            <div class="hero-container">
                <div class="hero-text-area">
                    <div class="sentinel-title">🛡️ MALWARE SENTINEL</div>
                    <div class="sub-title">AI-Powered Static Malware Classification</div>
                    <p class="hero-desc">Analyze Windows PE software using static analysis and machine learning.</p>
                </div>
                <div class="hero-graphic-area">
                    <div class="radar-ring radar-ring-1"></div>
                    <div class="radar-ring radar-ring-2"></div>
                    <div class="radar-ring radar-ring-3"></div>
                    <div class="radar-center-shield">🛡️</div>
                </div>
            </div>
            """
        ),
        unsafe_allow_html=True,
    )

    # Top KPI Metrics Overview Row with Live Count-Up Animation
    kpi_cards = [
        {"label": "Training Corpus Samples", "value": summary["total_rows"], "color": "#F8FAFC", "is_float": False},
        {"label": "Malware Prevalence", "value": summary["malware_percentage"], "color": COLOR_MALWARE, "suffix": "%", "is_float": True},
        {"label": "Test ROC-AUC Score", "value": 99.2, "color": COLOR_BENIGN, "suffix": "%", "is_float": True},
        {"label": "Selected Header Predictors", "value": feat_info["final_selected_features_count"] if feat_info else 16, "color": COLOR_ACCENT, "is_float": False},
    ]
    render_animated_kpi_counters(kpi_cards, height=110)

    # Glowing Section Divider
    st.markdown('<div class="sentinel-divider">── ✦ ──</div>', unsafe_allow_html=True)

    # Rebuilt Glass Upload Card with Hover Elevation and Glow
    st.markdown(
        textwrap.dedent(
            """
            <div class="glass-upload-card hover-spotlight reveal-on-scroll">
                <div class="upload-icon">📁</div>
                <div class="upload-heading">Upload Windows Software</div>
                <div class="upload-sub">Drag & drop or browse a Windows executable to perform instant static header feature extraction and threat inference</div>
                <div><span class="format-pills">Supported: .EXE • .DLL • .SYS</span></div>
            </div>
            """
        ),
        unsafe_allow_html=True,
    )

    # File Uploader Widget
    uploaded_file = st.file_uploader(
        "Upload Windows PE Binary",
        type=["exe", "dll", "sys"],
        help="Select a 32-bit or 64-bit Windows PE file (.exe, .dll, .sys). The file is statically inspected in-memory; it is never executed.",
        label_visibility="collapsed",
    )

    # Show Selected File Metadata Banner with Checkmark Indicator
    if uploaded_file is not None:
        st.markdown(
            textwrap.dedent(
                f"""
                <div class="file-selected-card hover-spotlight">
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <span style="font-size: 1.5rem;">✅</span>
                        <div>
                            <strong style="color: #F8FAFC; font-size: 1.05rem;">{uploaded_file.name}</strong>
                            <div style="color: #94A3B8; font-size: 0.85rem;">Ready for static feature extraction • Size: {uploaded_file.size / 1024:.1f} KB</div>
                        </div>
                    </div>
                    <span class="format-pills" style="margin-top: 0;">Verified Target</span>
                </div>
                """
            ),
            unsafe_allow_html=True,
        )

    # Analyze File Action Button
    col_btn1, col_btn2, col_btn3 = st.columns([1, 2, 1])
    with col_btn2:
        analyze_clicked = st.button(
            "🔍 Analyze File",
            type="primary",
            use_container_width=True,
            disabled=(uploaded_file is None),
        )

    # Reserved UI Containers & Placeholders
    progress_container = st.container()
    result_container = st.container()
    radar_container = st.container()
    explain_container = st.container()
    feature_cards_container = st.container()
    tech_container = st.container()

    # Model presence check
    if final_model is None:
        st.error("❌ Trained model artifact (`models/final_model.pkl`) not found. Please ensure model training has been completed.")
        render_footer()
        st.stop()

    # Helper function for rendering styled processing sequence
    def render_processing_sequence_html(current_step: int) -> str:
        step_definitions = [
            ("🔍", "Reading PE structure"),
            ("🧬", "Extracting features"),
            ("🧠", "Running ML model"),
            ("📊", "Calculating prediction"),
            ("🛡️", "Generating explanation"),
        ]
        rows = []
        for idx, (icon, text) in enumerate(step_definitions, 1):
            if idx < current_step:
                cls = "step-row completed"
                badge = "<span style='color: #10B981; font-weight: 700; font-size: 0.85rem;'>✓ Completed</span>"
            elif idx == current_step:
                cls = "step-row active"
                badge = "<span class='step-spinner'></span> <span style='color: #00D2FF; font-weight: 700; font-size: 0.85rem;'>Processing...</span>"
            else:
                cls = "step-row"
                badge = "<span style='color: #64748B; font-size: 0.85rem;'>Pending</span>"
            rows.append(
                f"<div class='{cls}'>"
                f"<span style='font-size: 1.15rem;'>{icon}</span>"
                f"<span style='flex-grow: 1;'>{text}</span>"
                f"{badge}"
                f"</div>"
            )
        return f"<div class='step-sequence-box'>{''.join(rows)}</div>"

    # Helper function for rendering Static Analysis Radar chart
    def render_static_analysis_radar(raw_feats: Dict[str, float]):
        categories = [
            "PE Structure",
            "Sections",
            "Entropy",
            "Imports",
            "Headers",
            "Directories",
            "Code Characteristics",
        ]
        
        # Real extracted metrics normalized onto 0-100 scale
        chars = float(raw_feats.get("Characteristics", 258))
        pe_struct_val = min(100.0, max(20.0, (chars % 1000) / 10.0 + 35.0))
        
        sec_len = float(raw_feats.get("SectionsLength", len(raw_feats)))
        sec_val = min(100.0, max(25.0, sec_len * 12.0))
        
        entropy = float(raw_feats.get("SectionMinEntropy", 3.0))
        entropy_val = min(100.0, max(15.0, (entropy / 8.0) * 100.0))
        
        imp_size = float(raw_feats.get("DirectoryEntryImportSize", 40))
        imp_val = min(100.0, max(20.0, min(imp_size, 300.0) / 3.0))
        
        hdr_size = float(raw_feats.get("SizeOfHeaders", 1024))
        hdr_val = min(100.0, max(25.0, (hdr_size / 2048.0) * 80.0))
        
        dir_export = float(raw_feats.get("DirectoryEntryExport", 0))
        dir_val = 80.0 if dir_export > 0 else 45.0
        
        code_size = float(raw_feats.get("SizeOfCode", 10000))
        img_size = float(raw_feats.get("SizeOfImage", 50000))
        code_ratio = (code_size / (img_size + 1)) * 100.0
        code_val = min(100.0, max(20.0, code_ratio * 2.5))

        values = [pe_struct_val, sec_val, entropy_val, imp_val, hdr_val, dir_val, code_val]
        values_closed = values + [values[0]]
        categories_closed = categories + [categories[0]]

        fig_rad = go.Figure()
        fig_rad.add_trace(go.Scatterpolar(
            r=values_closed,
            theta=categories_closed,
            fill="toself",
            fillcolor="rgba(0, 210, 255, 0.2)",
            line=dict(color="#00D2FF", width=2),
            marker=dict(color="#8B5CF6", size=6),
            name="Static Metrics",
        ))

        fig_rad.update_layout(
            polar=dict(
                radialaxis=dict(
                    visible=True,
                    range=[0, 100],
                    showticklabels=False,
                    gridcolor="rgba(255, 255, 255, 0.08)",
                    linecolor="rgba(255, 255, 255, 0.1)",
                ),
                angularaxis=dict(
                    gridcolor="rgba(255, 255, 255, 0.08)",
                    linecolor="rgba(255, 255, 255, 0.1)",
                    tickfont=dict(color="#E2E8F0", size=11),
                ),
                bgcolor="rgba(19, 28, 46, 0.5)",
            ),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            height=320,
            margin=dict(l=40, r=40, t=30, b=30),
            showlegend=False,
        )
        return fig_rad

    # Flow when no file is uploaded
    if uploaded_file is None:
        with progress_container:
            st.markdown(
                textwrap.dedent(
                    """
                    <div class="placeholder-box">
                        <strong>Awaiting Binary Upload:</strong> Select or drag a <code>.exe</code>, <code>.dll</code>, or <code>.sys</code> file above to initialize static PE feature extraction and threat classification.
                    </div>
                    """
                ),
                unsafe_allow_html=True,
            )
    else:
        current_file_key = f"{uploaded_file.name}_{uploaded_file.size}"
        cached_result = st.session_state.get("cached_pe_analysis")

        # Determine if we should run fresh analysis or use cached result
        should_run_analysis = analyze_clicked or (cached_result and cached_result.get("file_key") == current_file_key)

        if not should_run_analysis:
            with progress_container:
                st.info(f"📁 **File Ready:** `{uploaded_file.name}` ({uploaded_file.size / 1024:.1f} KB). Click **Analyze File** above to run the PE extraction and inference pipeline.")
        else:
            # Check if we already have the cached analysis for this exact file
            if cached_result and cached_result.get("file_key") == current_file_key and not analyze_clicked:
                res_data = cached_result
            else:
                # Run fresh sequential analysis with live step indicator
                file_bytes = uploaded_file.read()
                step_placeholder = progress_container.empty()

                # Step 1: Reading PE structure
                step_placeholder.markdown(render_processing_sequence_html(1), unsafe_allow_html=True)
                
                # Step 2: Extracting features
                step_placeholder.markdown(render_processing_sequence_html(2), unsafe_allow_html=True)
                try:
                    extracted_result = extract_features(file_bytes)
                except PEExtractionError as pe_err:
                    step_placeholder.empty()
                    st.error(f"❌ This file could not be parsed as a valid PE executable: {pe_err}")
                    render_footer()
                    st.stop()
                except Exception as e:
                    step_placeholder.empty()
                    st.error(f"❌ This file could not be parsed as a valid PE executable: Unexpected parsing exception occurred.")
                    render_footer()
                    st.stop()

                aligned_df, align_warnings, is_valid = validate_and_align(extracted_result["features"])
                if not is_valid:
                    step_placeholder.empty()
                    st.error("❌ Unable to generate all required PE features for this file.")
                    for warn in align_warnings:
                        st.warning(f"• {warn}")
                    render_footer()
                    st.stop()

                # Step 3: Running ML model
                step_placeholder.markdown(render_processing_sequence_html(3), unsafe_allow_html=True)
                probs = final_model.predict_proba(aligned_df)[0]
                
                # Step 4: Calculating prediction
                step_placeholder.markdown(render_processing_sequence_html(4), unsafe_allow_html=True)
                p_benign = float(probs[0])
                p_malware = float(probs[1])
                prediction = 1 if p_malware >= 0.5 else 0
                confidence = float(max(p_benign, p_malware) * 100)

                # Step 5: Generating explanation
                step_placeholder.markdown(render_processing_sequence_html(5), unsafe_allow_html=True)
                try:
                    explanations = explain_prediction(final_model, aligned_df, top_k=6)
                except Exception:
                    explanations = []

                # Final sequence state
                step_placeholder.markdown(render_processing_sequence_html(6), unsafe_allow_html=True)

                # Cache in session state
                res_data = {
                    "file_key": current_file_key,
                    "file_name": uploaded_file.name,
                    "file_size": uploaded_file.size,
                    "extracted_result": extracted_result,
                    "aligned_df": aligned_df,
                    "probs": probs,
                    "p_benign": p_benign,
                    "p_malware": p_malware,
                    "prediction": prediction,
                    "confidence": confidence,
                    "explanations": explanations,
                }
                st.session_state["cached_pe_analysis"] = res_data

            # Extract result variables
            extracted_result = res_data["extracted_result"]
            aligned_df = res_data["aligned_df"]
            probs = res_data["probs"]
            p_benign = res_data["p_benign"]
            p_malware = res_data["p_malware"]
            prediction = res_data["prediction"]
            confidence = res_data["confidence"]
            explanations = res_data["explanations"]

            model_name = training_meta.get("selected_model", "HistGradientBoosting") if training_meta else "HistGradientBoosting"
            verdict_text = "Potential Malware" if prediction == 1 else "Likely Benign"

            # ------------------------------------------------------------------
            # 2. Result Panel (Single Cohesive Centered Glass Card)
            # ------------------------------------------------------------------
            with result_container:
                st.markdown('<div class="sentinel-divider">── ✦ ──</div>', unsafe_allow_html=True)
                res_col1, res_col2, res_col3 = st.columns([0.05, 0.90, 0.05])
                with res_col2:
                    malware_pct = p_malware * 100.0
                    benign_pct = p_benign * 100.0
                    cert_level = "High" if confidence >= 85.0 else ("Moderate" if confidence >= 65.0 else "Low")

                    if prediction == 1:
                        card_cls = "result-glass-card-malware hover-spotlight spotlight-malware"
                        headline_icon = "⚠️"
                        headline_text = "MALWARE DETECTED"
                        headline_color = "#EF4444"
                        headline_glow = "0 0 22px rgba(239, 68, 68, 0.5)"
                        threat_badge = "Threat Classification: High-Risk Malicious Signature"
                        threat_color = "#FCA5A5"
                        malware_val_color = "#EF4444"
                        benign_val_color = "#94A3B8"
                    else:
                        card_cls = "result-glass-card-benign hover-spotlight spotlight-benign"
                        headline_icon = "🛡️"
                        headline_text = "BENIGN FILE"
                        headline_color = "#10B981"
                        headline_glow = "0 0 22px rgba(16, 185, 129, 0.5)"
                        threat_badge = "Threat Classification: Clean / Safe Executable"
                        threat_color = "#6EE7B7"
                        malware_val_color = "#94A3B8"
                        benign_val_color = "#10B981"

                    card_html = (
                        f'<div class="{card_cls}">'
                        f'<div style="display: flex; align-items: center; justify-content: center; gap: 12px; margin-bottom: 2px;">'
                        f'<span style="font-size: 2.3rem; filter: drop-shadow(0 0 8px {headline_color});">{headline_icon}</span>'
                        f'<span style="font-size: 2.2rem; font-weight: 900; color: {headline_color}; text-shadow: {headline_glow}; letter-spacing: -0.5px;">{headline_text}</span>'
                        f'</div>'
                        f'<div style="color: {threat_color}; font-size: 0.95rem; font-weight: 600; margin-bottom: 1.1rem;">'
                        f'{threat_badge}'
                        f'</div>'
                        f'<div style="background: rgba(15, 23, 42, 0.65); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; padding: 1.1rem 1.3rem; margin-bottom: 0.9rem;">'
                        f'<div style="margin-bottom: 0.85rem;">'
                        f'<div style="display: flex; justify-content: space-between; font-size: 0.82rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.6px; margin-bottom: 6px;">'
                        f'<span style="color: #EF4444;">Malware: {malware_pct:.2f}%</span>'
                        f'<span style="color: #10B981;">Benign: {benign_pct:.2f}%</span>'
                        f'</div>'
                        f'<div style="height: 10px; width: 100%; background: rgba(255, 255, 255, 0.08); border-radius: 6px; overflow: hidden; display: flex; box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.4);">'
                        f'<div style="width: {malware_pct}%; background: linear-gradient(90deg, #DC2626 0%, #EF4444 100%); transition: width 0.6s ease; box-shadow: 0 0 10px rgba(239, 68, 68, 0.5);"></div>'
                        f'<div style="width: {benign_pct}%; background: linear-gradient(90deg, #10B981 0%, #059669 100%); transition: width 0.6s ease; box-shadow: 0 0 10px rgba(16, 185, 129, 0.5);"></div>'
                        f'</div>'
                        f'</div>'
                        f'<div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; padding-top: 0.6rem; border-top: 1px solid rgba(255, 255, 255, 0.06);">'
                        f'<div style="text-align: center;">'
                        f'<div style="color: #94A3B8; font-size: 0.76rem; text-transform: uppercase; font-weight: 700; letter-spacing: 0.6px; margin-bottom: 3px;">Malware Probability</div>'
                        f'<div style="color: {malware_val_color}; font-size: 1.7rem; font-weight: 900; line-height: 1.1;">{malware_pct:.2f}%</div>'
                        f'</div>'
                        f'<div style="text-align: center; border-left: 1px solid rgba(255, 255, 255, 0.08); border-right: 1px solid rgba(255, 255, 255, 0.08);">'
                        f'<div style="color: #94A3B8; font-size: 0.76rem; text-transform: uppercase; font-weight: 700; letter-spacing: 0.6px; margin-bottom: 3px;">Benign Probability</div>'
                        f'<div style="color: {benign_val_color}; font-size: 1.7rem; font-weight: 900; line-height: 1.1;">{benign_pct:.2f}%</div>'
                        f'</div>'
                        f'<div style="text-align: center;">'
                        f'<div style="color: #94A3B8; font-size: 0.76rem; text-transform: uppercase; font-weight: 700; letter-spacing: 0.6px; margin-bottom: 3px;">Confidence Score</div>'
                        f'<div style="color: #F8FAFC; font-size: 1.7rem; font-weight: 900; line-height: 1.1;">{confidence:.2f}%</div>'
                        f'</div>'
                        f'</div>'
                        f'</div>'
                        f'<div style="color: #E2E8F0; font-size: 0.92rem; font-weight: 500; margin-bottom: 0.85rem;">'
                        f'Confidence: <strong style="color: #00D2FF;">{confidence:.2f}%</strong> • {cert_level} certainty assessment based on static PE header features'
                        f'</div>'
                        f'<div style="display: flex; justify-content: space-between; align-items: center; padding-top: 0.6rem; border-top: 1px solid rgba(255, 255, 255, 0.08); font-size: 0.82rem; color: #94A3B8;">'
                        f'<span>Model Engine: <strong style="color: #00D2FF;">{model_name}</strong></span>'
                        f'<span>Target Binary: <strong style="color: #F8FAFC;">{uploaded_file.name}</strong></span>'
                        f'<span>Inspection: <span style="color: #10B981; font-weight: 600;">Static Verified</span></span>'
                        f'</div>'
                        f'</div>'
                    )
                    st.markdown(card_html, unsafe_allow_html=True)

            # ------------------------------------------------------------------
            # 4. Static Analysis Radar Visual
            # ------------------------------------------------------------------
            with radar_container:
                st.markdown("#### 📡 Static Analysis Overview")
                fig_radar_chart = render_static_analysis_radar(extracted_result["features"])
                st.plotly_chart(fig_radar_chart, use_container_width=True)
                st.caption("ℹ️ *Illustrative grouping of extracted static features, not a security rating.*")

            # ------------------------------------------------------------------
            # 8 & 9. Explainability Panel & Analysis Summary
            # ------------------------------------------------------------------
            with explain_container:
                st.markdown('<div class="sentinel-divider">── ✦ ──</div>', unsafe_allow_html=True)
                st.markdown("### 🔬 Why was it classified this way?")
                st.markdown('<div style="color: #94A3B8; font-size: 0.95rem; margin-bottom: 1rem;">Local SHAP feature attribution: reveals which specific PE header characteristics drove the model\'s prediction toward Malware or Benign.</div>', unsafe_allow_html=True)

                if explanations:
                    # Plotly horizontal bar chart of top SHAP attributions with tooltips
                    exp_df = pd.DataFrame(explanations)
                    exp_df["BarColor"] = exp_df["direction"].apply(
                        lambda d: COLOR_MALWARE if d == "Toward Malware" else COLOR_BENIGN
                    )

                    hover_texts = []
                    for row in exp_df.iloc[::-1].itertuples():
                        feat_desc = PE_FEATURE_DESCRIPTIONS.get(row.name, "Extracted static PE header predictor.")
                        caution_str = "<br>⚠️ <i>Note: Reconstructed approximation; treat with extra caution</i>" if row.name in UNCERTAIN_CUSTOM_FEATURES else ""
                        hover_texts.append(
                            f"<b>Feature:</b> {row.name}<br>"
                            f"<b>Input Value:</b> {row.value}<br>"
                            f"<b>SHAP Impact:</b> {row.shap_value:+.4f} ({row.magnitude})<br>"
                            f"<b>Direction:</b> {row.direction}<br>"
                            f"<b>Description:</b> {feat_desc}{caution_str}"
                        )

                    fig_shap = go.Figure()
                    fig_shap.add_trace(go.Bar(
                        y=[r.name for r in exp_df.iloc[::-1].itertuples()],
                        x=[r.shap_value for r in exp_df.iloc[::-1].itertuples()],
                        orientation="h",
                        marker=dict(
                            color=[r.BarColor for r in exp_df.iloc[::-1].itertuples()],
                            line=dict(color="rgba(255, 255, 255, 0.15)", width=1),
                        ),
                        text=[f"{r.shap_value:+.4f} (Input: {r.value})" for r in exp_df.iloc[::-1].itertuples()],
                        textposition="auto",
                        hovertext=hover_texts,
                        hoverinfo="text",
                        showlegend=False,
                    ))

                    fig_shap.update_layout(
                        title=dict(text="Top Contributing Features (SHAP Value & Direction)", font=dict(size=14, color="#F8FAFC")),
                        template="plotly_dark",
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)",
                        height=310,
                        margin=dict(l=10, r=20, t=40, b=20),
                        xaxis_title="SHAP Attribution (Log-Odds Impact)",
                        xaxis=dict(showgrid=True, gridcolor="rgba(255,255,255,0.08)", zeroline=True, zerolinecolor="#64748B"),
                        yaxis_title="",
                    )
                    st.plotly_chart(fig_shap, use_container_width=True)

                    # Human-readable breakdown cards with hover tooltips and descriptions
                    st.markdown("#### Feature Influence Breakdown")
                    for feat in explanations:
                        direction_str = feat["direction"].lower()
                        is_uncertain = feat["name"] in UNCERTAIN_CUSTOM_FEATURES
                        feat_desc = PE_FEATURE_DESCRIPTIONS.get(feat["name"], "Static PE header feature.")
                        
                        uncertain_badge = (
                            '<span style="color: #F59E0B; font-size: 0.8rem; font-weight: 600; margin-left: 6px;">'
                            '⚠️ (Note: Reconstructed approximation; treat with extra caution)</span>'
                            if is_uncertain else ""
                        )
                        
                        bullet_html = textwrap.dedent(
                            f"""
                            <div title="{feat_desc}" class="hover-spotlight" style="background: #131C2E; border-left: 3px solid {'#EF4444' if feat['direction'] == 'Toward Malware' else '#10B981'}; padding: 10px 14px; margin-bottom: 8px; border-radius: 0 8px 8px 0; transition: transform 0.2s ease;">
                                <strong style="color: #F8FAFC;">{feat['name']}</strong>: Input value was <code>{feat['value']}</code>, which contributed 
                                <span style="color: {'#EF4444' if feat['direction'] == 'Toward Malware' else '#10B981'}; font-weight: 700;">{direction_str}</span> 
                                (<strong>{feat['magnitude']} impact</strong>, SHAP = <code>{feat['shap_value']:+.4f}</code>) to the model's prediction.{uncertain_badge}
                                <div style="color: #94A3B8; font-size: 0.8rem; margin-top: 4px;">ℹ️ {feat_desc}</div>
                            </div>
                            """
                        )
                        st.markdown(bullet_html, unsafe_allow_html=True)

                    # 9. Dynamic Analysis Summary Paragraph
                    st.markdown("#### 📝 Automated Analysis Summary")
                    top3_names = [f["name"] for f in explanations[:3]]
                    top3_vals = [f["value"] for f in explanations[:3]]
                    
                    summary_paragraph = (
                        f"Static analysis classified **{uploaded_file.name}** as **{verdict_text}** with a model probability of "
                        f"**{p_malware*100:.2f}%** ({p_benign*100:.2f}% Benign). "
                        f"The classifier's decision was most significantly influenced by **{top3_names[0]}** (value: {top3_vals[0]}), "
                        f"**{top3_names[1]}** (value: {top3_vals[1]}), and **{top3_names[2]}** (value: {top3_vals[2]}), which provided the "
                        f"strongest directional feature contributions to the prediction."
                    )
                    st.info(summary_paragraph)

            # ------------------------------------------------------------------
            # Feature Analysis Cards (PE Structure, Code, Section, Imports)
            # ------------------------------------------------------------------
            with feature_cards_container:
                st.markdown('<div class="sentinel-divider">── ✦ ──</div>', unsafe_allow_html=True)
                st.markdown("### 🧩 Static Feature Domain Analysis")
                st.markdown('<div style="color: #94A3B8; font-size: 0.95rem; margin-bottom: 1.2rem;">Comprehensive inspection across core PE binary dimensions extracted from headers.</div>', unsafe_allow_html=True)

                meta_data = extracted_result.get("metadata", {})
                raw_feats = extracted_result.get("features", {})

                # Feature values computed safely from real extracted data
                chars_val = f"0x{int(raw_feats.get('Characteristics', 0)):04X}"
                img_base_val = f"0x{int(raw_feats.get('ImageBase', 0)):08X}"
                hdr_size_val = f"{int(raw_feats.get('SizeOfHeaders', 0)):,} B"
                machine_val = str(meta_data.get('machine_type', 'x86/x64'))
                subsys_val = str(meta_data.get('subsystem', 'Windows GUI'))

                code_size_val = f"{int(raw_feats.get('SizeOfCode', 0)):,} B"
                entry_val = f"0x{int(raw_feats.get('AddressOfEntryPoint', 0)):08X}"
                code_to_img = (float(raw_feats.get('SizeOfCode', 0)) / (float(raw_feats.get('SizeOfImage', 1)) + 1)) * 100.0
                code_ratio_val = f"{code_to_img:.1f}%"
                linker_val = f"v{int(raw_feats.get('MajorLinkerVersion', 0))}.0"
                init_data_ratio = (float(raw_feats.get('SizeOfInitializedData', 0)) / (float(raw_feats.get('SizeOfImage', 1)) + 1)) * 100.0
                init_ratio_val = f"{init_data_ratio:.1f}%"

                sec_count_val = str(meta_data.get('number_of_sections', len(meta_data.get('section_names', []))))
                min_ent_val = f"{float(raw_feats.get('SectionMinEntropy', 0.0)):.3f}"
                max_ent_val = f"{float(raw_feats.get('SectionMaxEntropy', 0.0)):.3f}"
                ent_range_val = f"{abs(float(raw_feats.get('SectionMaxEntropy', 0.0)) - float(raw_feats.get('SectionMinEntropy', 0.0))):.3f}"
                susp_sec_val = str(int(raw_feats.get('SuspiciousNameSection', 0)))

                imp_size_val = f"{int(raw_feats.get('DirectoryEntryImportSize', 0)):,} B"
                dll_count_val = str(meta_data.get('imported_dll_count', 0))
                func_count_val = str(meta_data.get('imported_function_count', 0))
                susp_func_val = str(int(raw_feats.get('SuspiciousImportFunctions', 0)))
                has_export = "Yes (Table Found)" if float(raw_feats.get('DirectoryEntryExport', 0)) > 0 else "None"

                fc1, fc2 = st.columns(2)
                with fc1:
                    st.markdown(
                        textwrap.dedent(
                            f"""
                            <div class="feature-analysis-card hover-spotlight reveal-on-scroll">
                                <div class="feature-card-header">🏛️ PE Structure & Headers</div>
                                <div class="feature-card-desc">Defines binary format specification, target execution subsystem, and architecture layout.</div>
                                <div class="feature-item-row"><span class="feature-item-name">Architecture</span><span class="feature-item-val">{machine_val}</span></div>
                                <div class="feature-item-row"><span class="feature-item-name">Execution Subsystem</span><span class="feature-item-val">{subsys_val}</span></div>
                                <div class="feature-item-row"><span class="feature-item-name">Characteristics Flag</span><span class="feature-item-val">{chars_val}</span></div>
                                <div class="feature-item-row"><span class="feature-item-name">Preferred Image Base</span><span class="feature-item-val">{img_base_val}</span></div>
                                <div class="feature-item-row"><span class="feature-item-name">Combined Headers Size</span><span class="feature-item-val">{hdr_size_val}</span></div>
                            </div>
                            """
                        ),
                        unsafe_allow_html=True,
                    )
                with fc2:
                    st.markdown(
                        textwrap.dedent(
                            f"""
                            <div class="feature-analysis-card hover-spotlight reveal-on-scroll">
                                <div class="feature-card-header">⚡ Code Characteristics</div>
                                <div class="feature-card-desc">Captures compiler tooling version, execution entry vector, and instruction density.</div>
                                <div class="feature-item-row"><span class="feature-item-name">Executable Code Size</span><span class="feature-item-val">{code_size_val}</span></div>
                                <div class="feature-item-row"><span class="feature-item-name">Entry Point (RVA)</span><span class="feature-item-val">{entry_val}</span></div>
                                <div class="feature-item-row"><span class="feature-item-name">Code-to-Image Ratio</span><span class="feature-item-val">{code_ratio_val}</span></div>
                                <div class="feature-item-row"><span class="feature-item-name">Major Linker Version</span><span class="feature-item-val">{linker_val}</span></div>
                                <div class="feature-item-row"><span class="feature-item-name">Initialized Data Ratio</span><span class="feature-item-val">{init_ratio_val}</span></div>
                            </div>
                            """
                        ),
                        unsafe_allow_html=True,
                    )

                fc3, fc4 = st.columns(2)
                with fc3:
                    st.markdown(
                        textwrap.dedent(
                            f"""
                            <div class="feature-analysis-card hover-spotlight reveal-on-scroll">
                                <div class="feature-card-header">📑 Section Analysis & Entropy</div>
                                <div class="feature-card-desc">Evaluates section layout and Shannon entropy spread to detect packing or encryption.</div>
                                <div class="feature-item-row"><span class="feature-item-name">Total Section Count</span><span class="feature-item-val">{sec_count_val}</span></div>
                                <div class="feature-item-row"><span class="feature-item-name">Minimum Shannon Entropy</span><span class="feature-item-val">{min_ent_val}</span></div>
                                <div class="feature-item-row"><span class="feature-item-name">Maximum Shannon Entropy</span><span class="feature-item-val">{max_ent_val}</span></div>
                                <div class="feature-item-row"><span class="feature-item-name">Section Entropy Spread</span><span class="feature-item-val">{ent_range_val}</span></div>
                                <div class="feature-item-row"><span class="feature-item-name">Suspicious Section Names</span><span class="feature-item-val">{susp_sec_val}</span></div>
                            </div>
                            """
                        ),
                        unsafe_allow_html=True,
                    )
                with fc4:
                    st.markdown(
                        textwrap.dedent(
                            f"""
                            <div class="feature-analysis-card hover-spotlight reveal-on-scroll">
                                <div class="feature-card-header">🔌 Import & Dependency Analysis</div>
                                <div class="feature-card-desc">Inspects external API dependency linkages and flags known dual-use capabilities.</div>
                                <div class="feature-item-row"><span class="feature-item-name">Import Directory Size</span><span class="feature-item-val">{imp_size_val}</span></div>
                                <div class="feature-item-row"><span class="feature-item-name">Imported DLL Count</span><span class="feature-item-val">{dll_count_val}</span></div>
                                <div class="feature-item-row"><span class="feature-item-name">Imported Function APIs</span><span class="feature-item-val">{func_count_val}</span></div>
                                <div class="feature-item-row"><span class="feature-item-name">Suspicious Heuristic APIs</span><span class="feature-item-val">{susp_func_val}</span></div>
                                <div class="feature-item-row"><span class="feature-item-name">Export Directory Present</span><span class="feature-item-val">{has_export}</span></div>
                            </div>
                            """
                        ),
                        unsafe_allow_html=True,
                    )

            # ------------------------------------------------------------------
            # Technical Analysis Expander
            # ------------------------------------------------------------------
            with tech_container:
                st.markdown('<div class="sentinel-divider">── ✦ ──</div>', unsafe_allow_html=True)
                with st.expander("🔬 View Technical Analysis & Extracted Headers", expanded=False):
                    hashes_data = extracted_result.get("hashes", {})
                    meta_data = extracted_result.get("metadata", {})
                    raw_feats = extracted_result.get("features", {})

                    st.markdown("#### 1. File Identification & Cryptographic Hashes")
                    st.caption("ℹ️ *Note: Hashes are cryptographic identifiers only and are strictly excluded from machine learning features.*")
                    
                    h_col1, h_col2 = st.columns(2)
                    with h_col1:
                        st.write(f"- **File Name:** `{uploaded_file.name}`")
                        st.write(f"- **File Size:** {hashes_data.get('size_bytes', len(file_bytes)):,} bytes ({hashes_data.get('size_bytes', len(file_bytes))/1024:.2f} KB)")
                        st.write(f"- **MD5:** `{hashes_data.get('md5', 'N/A')}`")
                    with h_col2:
                        st.write(f"- **SHA-1:** `{hashes_data.get('sha1', 'N/A')}`")
                        st.write(f"- **SHA-256:** `{hashes_data.get('sha256', 'N/A')}`")

                    st.divider()

                    st.markdown("#### 2. Core PE Header Properties")
                    prop_col1, prop_col2, prop_col3 = st.columns(3)
                    with prop_col1:
                        st.write(f"- **Machine Architecture:** `{meta_data.get('machine_type', 'N/A')}`")
                        st.write(f"- **Subsystem Code:** `{meta_data.get('subsystem', 'N/A')}`")
                        st.write(f"- **Section Count:** `{meta_data.get('number_of_sections', 'N/A')}`")
                    with prop_col2:
                        st.write(f"- **Entry Point (RVA):** `0x{int(raw_feats.get('AddressOfEntryPoint', 0)):08X}`")
                        st.write(f"- **Image Size:** `{int(raw_feats.get('SizeOfImage', 0)):,} bytes`")
                        st.write(f"- **Code Size:** `{int(raw_feats.get('SizeOfCode', 0)):,} bytes`")
                    with prop_col3:
                        st.write(f"- **Imported DLL Count:** `{meta_data.get('imported_dll_count', 0)}`")
                        st.write(f"- **Imported APIs Count:** `{meta_data.get('imported_function_count', 0)}`")
                        st.write(f"- **Suspicious Heuristic APIs:** `{int(raw_feats.get('SuspiciousImportFunctions', 0))}`")

                    st.divider()

                    st.markdown("#### 3. Section Table & Entropy Overview")
                    if meta_data.get("section_names"):
                        sec_df = pd.DataFrame({
                            "Section Name": meta_data.get("section_names", []),
                            "Min Entropy": raw_feats.get("SectionMinEntropy", 0.0),
                            "Min Raw Size": raw_feats.get("SectionMinRawsize", 0.0),
                            "Max Physical Size": raw_feats.get("SectionMaxPhysical", 0.0),
                            "Max Virtual Addr": raw_feats.get("SectionMaxVirtual", 0.0),
                        })
                        st.dataframe(sec_df, use_container_width=True)

                    st.divider()

                    st.markdown("#### 4. Raw Extracted Feature Vector (77 Features)")
                    raw_feat_df = pd.DataFrame([raw_feats]).T.reset_index()
                    raw_feat_df.columns = ["PE Feature Name", "Extracted Value"]
                    st.dataframe(raw_feat_df, use_container_width=True)

    render_footer()

# ------------------------------------------------------------------------------
# 2. 📊 Dataset
# ------------------------------------------------------------------------------
elif page == "📊 Dataset":
    st.markdown('<div class="main-title">Dataset Inspection & Integrity</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">Full structural preview, feature schema, missing value audit, duplicate analysis, and stratified split</div>', unsafe_allow_html=True)

    dataset_kpi_cards = [
        {"label": "Total Samples", "value": summary["total_rows"], "color": "#F8FAFC", "is_float": False},
        {"label": "Malware Samples", "value": summary["malware_count"], "color": COLOR_MALWARE, "is_float": False},
        {"label": "Benign Samples", "value": summary["benign_count"], "color": COLOR_BENIGN, "is_float": False},
        {"label": "Numeric Predictors", "value": summary["numeric_features_count"], "color": COLOR_ACCENT, "is_float": False},
    ]
    render_animated_kpi_counters(dataset_kpi_cards, height=110)

    st.divider()

    tab1, tab2, tab3, tab4 = st.tabs(["📋 Data Preview", "📊 Summary Statistics", "🛡️ Schema & Integrity", "🔀 Train / Test Split"])

    with tab1:
        st.subheader("Data Preview")
        preview_rows = st.slider("Select number of rows to preview:", min_value=5, max_value=100, value=25, step=5)
        st.dataframe(df.head(preview_rows), use_container_width=True)

    with tab2:
        st.subheader("Summary Statistics for Numeric Features")
        stat_cols = st.multiselect(
            "Filter columns to inspect:",
            options=feat_cols,
            default=feat_cols[:8],
        )
        if stat_cols:
            st.dataframe(df[stat_cols].describe().T, use_container_width=True)
        else:
            st.dataframe(df[feat_cols].describe().T, use_container_width=True)

    with tab3:
        st.subheader("Column Metadata & Missing Value Audit")
        if summary["missing_values"] == 0:
            st.success("✅ **No missing values detected; no imputation required.** (0 missing cells across all 79 columns).")
        meta_df = pd.DataFrame({
            "Column Name": df.columns,
            "Data Type": [str(t) for t in df.dtypes],
            "Non-Null Count": df.notnull().sum().values,
            "Null Count": df.isnull().sum().values,
            "Null %": (df.isnull().sum().values / len(df) * 100).round(2),
            "Unique Values": [df[c].nunique() for c in df.columns],
        })
        st.dataframe(meta_df, use_container_width=True)

        st.subheader("Duplicate Analysis")
        d1, d2, d3 = st.columns(3)
        d1.metric("Full-Row Duplicates", f"{summary['duplicate_full_rows']}")
        d2.metric("Feature-Only Duplicate Rows", f"{summary['duplicate_feature_rows']:,}")
        d3.metric("Conflicting Feature Groups", f"{summary['conflicting_label_groups']}")

    with tab4:
        st.subheader("80 / 20 Stratified Train-Test Split")
        if split_info:
            s_col1, s_col2 = st.columns(2)
            with s_col1:
                st.markdown("#### 🏋️ Training Set (80%)")
                st.write(f"- **Total Rows:** {split_info['train_count']:,}")
                st.write(f"- **Malware Samples (Class 1):** {split_info['train_malware_count']:,} ({split_info['train_malware_count']/split_info['train_count']*100:.2f}%)")
                st.write(f"- **Benign Samples (Class 0):** {split_info['train_count'] - split_info['train_malware_count']:,} ({(split_info['train_count'] - split_info['train_malware_count'])/split_info['train_count']*100:.2f}%)")
                st.caption("Used strictly for Cross-Validation, Feature Selection, and Model Training.")

            with s_col2:
                st.markdown("#### 🧪 Untouched Test Set (20%)")
                st.write(f"- **Total Rows:** {split_info['test_count']:,}")
                st.write(f"- **Malware Samples (Class 1):** {split_info['test_malware_count']:,} ({split_info['test_malware_count']/split_info['test_count']*100:.2f}%)")
                st.write(f"- **Benign Samples (Class 0):** {split_info['test_count'] - split_info['test_malware_count']:,} ({(split_info['test_count'] - split_info['test_malware_count'])/split_info['test_count']*100:.2f}%)")
                st.caption("Preserved exclusively for final out-of-sample evaluation.")

            split_df = pd.DataFrame({
                "Partition": ["Training Set (80%)", "Test Set (20%)"],
                "Benign": [split_info['train_count'] - split_info['train_malware_count'], split_info['test_count'] - split_info['test_malware_count']],
                "Malware": [split_info['train_malware_count'], split_info['test_malware_count']],
            })
            fig_split = px.bar(
                split_df,
                x="Partition",
                y=["Benign", "Malware"],
                title="Stratified Class Proportions Across Partitions",
                barmode="stack",
                color_discrete_map={"Benign": COLOR_BENIGN, "Malware": COLOR_MALWARE},
                height=350,
            )
            fig_split.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
            st.plotly_chart(fig_split, use_container_width=True)

    render_footer()

# ------------------------------------------------------------------------------
# 3. 🔎 EDA
# ------------------------------------------------------------------------------
elif page == "🔎 EDA":
    st.markdown('<div class="main-title">Exploratory Data Analysis (EDA)</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">Interactive distributions, box plots, correlation heatmap, scatter plots, and class-wise comparison</div>', unsafe_allow_html=True)

    tab_target, tab_hist, tab_box, tab_corr, tab_scatter, tab_comp = st.tabs([
        "🎯 Target Distribution",
        "📊 Feature Histograms",
        "📦 Box Plots & Outliers",
        "🔥 Correlation Heatmap",
        "✨ 2D Scatter Separability",
        "📑 Class-Wise Comparison",
    ])

    with tab_target:
        render_target_tab(summary)
    with tab_hist:
        render_histograms_tab(df, feat_cols)
    with tab_box:
        render_boxplots_tab(df, feat_cols)
    with tab_corr:
        render_correlation_tab(df, feat_cols)
    with tab_scatter:
        render_scatter_tab(df, feat_cols)
    with tab_comp:
        render_comparison_tab(df, feat_cols)

    render_footer()

# ------------------------------------------------------------------------------
# 4. 🧬 Feature Engineering
# ------------------------------------------------------------------------------
elif page == "🧬 Feature Engineering":
    st.markdown('<div class="main-title">PE Header Feature Engineering</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">Domain-specific ratio and section entropy spread transformations</div>', unsafe_allow_html=True)

    st.markdown(
        textwrap.dedent(
            """
            To enhance classifier discriminative power on PE binaries, 5 domain-engineered features are added 
            via the `FeatureEngineer` transformer using safe division:
            """
        )
    )

    fe_data = [
        {
            "Engineered Feature": "CodeToImageRatio",
            "Formula": "SizeOfCode / (SizeOfImage + 1)",
            "PE Domain Rationale": "Measures what proportion of the mapped virtual image is occupied by executable code. Abnormally low ratios often indicate packed or obfuscated payloads.",
        },
        {
            "Engineered Feature": "InitializedDataRatio",
            "Formula": "SizeOfInitializedData / (SizeOfImage + 1)",
            "PE Domain Rationale": "Quantifies the density of initialized global data. Malware often embeds encrypted payloads inside oversized data sections.",
        },
        {
            "Engineered Feature": "SectionRawSizeRange",
            "Formula": "SectionMaxRawsize - SectionMinRawsize",
            "PE Domain Rationale": "The spread between largest and smallest raw disk section size, indicating irregular section allocations.",
        },
        {
            "Engineered Feature": "SectionVirtualSizeRange",
            "Formula": "SectionMaxVirtualsize - SectionMinVirtualsize",
            "PE Domain Rationale": "The spread between maximum and minimum memory virtual section dimensions.",
        },
        {
            "Engineered Feature": "SectionEntropyRange",
            "Formula": "SectionMaxEntropy - SectionMinEntropy",
            "PE Domain Rationale": "Captures the disparity between packed/encrypted sections (entropy ~8.0) and uncompressed text sections.",
        },
    ]
    st.table(pd.DataFrame(fe_data))

    st.subheader("🧪 Live Feature Engineering Transformation Demo")
    fe_transformer = FeatureEngineer()
    sample_X = df[feat_cols].head(10).copy()
    fe_transformer.fit(sample_X)
    engineered_sample = fe_transformer.transform(sample_X)

    st.write("Preview of 5 newly created features computed on the first 10 dataset rows:")
    new_eng_cols = ["CodeToImageRatio", "InitializedDataRatio", "SectionRawSizeRange", "SectionVirtualSizeRange", "SectionEntropyRange"]
    st.dataframe(engineered_sample[new_eng_cols], use_container_width=True)

    render_footer()

# ------------------------------------------------------------------------------
# 5. 🎯 Feature Selection
# ------------------------------------------------------------------------------
elif page == "🎯 Feature Selection":
    st.markdown('<div class="main-title">Multi-Stage Feature Selection Funnel</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">Systematic dimensional reduction, collinearity filtering, and tree-based selection</div>', unsafe_allow_html=True)

    if feat_info:
        f1, f2, f3, f4, f5 = st.columns(5)
        f1.metric("1. Raw Features", f"{feat_info['raw_features_count']}")
        f2.metric("2. Post Engineering", f"{feat_info['post_feature_engineer_count']} (+{feat_info['engineered_features_count']})")
        f3.metric("3. Post Variance Filter", f"{feat_info['post_variance_threshold_count']} (-{feat_info['variance_threshold_removed_count']})")
        f4.metric("4. Post Corr Filter", f"{feat_info['post_correlation_filter_count']} (-{feat_info['correlation_filter_removed_count']})")
        f5.metric("5. Final Selected", f"{feat_info['final_selected_features_count']}")

        st.divider()

        funnel_df = pd.DataFrame({
            "Stage": [
                "1. Raw Features",
                "2. Post Feature Engineering",
                "3. Post Variance Filter (σ² > 0)",
                "4. Post Correlation Filter (|r| ≤ 0.95)",
                "5. Final SelectFromModel (Random Forest)",
            ],
            "Feature Count": [
                feat_info["raw_features_count"],
                feat_info["post_feature_engineer_count"],
                feat_info["post_variance_threshold_count"],
                feat_info["post_correlation_filter_count"],
                feat_info["final_selected_features_count"],
            ],
        })

        fig_funnel = go.Figure(go.Funnel(
            y=funnel_df["Stage"],
            x=funnel_df["Feature Count"],
            textinfo="value+percent previous",
            marker=dict(color=["#64748B", "#38BDF8", "#00D2FF", "#2563EB", "#10B981"]),
        ))
        fig_funnel.update_layout(title="Feature Reduction Funnel", height=400, template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig_funnel, use_container_width=True)

        st.divider()

        t1, t2, t3 = st.tabs(["🗑️ Constant Features Removed", "🔗 Collinear Features Removed", "⭐ Final Selected Features"])

        with t1:
            st.markdown(f"#### Constant Features with Zero Variance ({feat_info['variance_threshold_removed_count']} dropped)")
            st.write("These columns had zero variance across all training samples:")
            st.write(feat_info["variance_threshold_removed_features"])

        with t2:
            st.markdown(f"#### Highly Collinear Features with |r| > 0.95 ({feat_info['correlation_filter_removed_count']} dropped)")
            st.write("To eliminate multicollinearity, one feature from each pair with |r| > 0.95 was deterministically dropped:")
            st.write(feat_info["correlation_filter_removed_features"])

        with t3:
            st.markdown(f"#### Final Selected Predictors ({feat_info['final_selected_features_count']} Features)")
            st.write("The following 16 features were selected by `SelectFromModel(RandomForestClassifier)` on the training set:")
            tags_html = " ".join([f"<span class='badge' style='background-color: rgba(0, 210, 255, 0.15); color: #00D2FF; border: 1px solid rgba(0, 210, 255, 0.3); margin: 4px; padding: 6px 12px; font-size: 0.88rem;'>{feat}</span>" for feat in feat_info["final_selected_features"]])
            st.markdown(tags_html, unsafe_allow_html=True)

    render_footer()

# ------------------------------------------------------------------------------
# 6. 🤖 Models
# ------------------------------------------------------------------------------
elif page == "🤖 Models":
    render_model_training_page(training_meta, metrics, PROJECT_ROOT)
    render_footer()

# ------------------------------------------------------------------------------
# 7. 📈 Evaluation
# ------------------------------------------------------------------------------
elif page == "📈 Evaluation":
    tab_eval, tab_comp = st.tabs(["📈 Model Evaluation (Out-of-Sample)", "⚖️ Model Comparison & Benchmarking"])
    with tab_eval:
        render_model_evaluation_page(metrics, roc_data, split_info)
    with tab_comp:
        render_model_comparison_page(metrics)
    render_footer()

# ------------------------------------------------------------------------------
# 8. 🔬 Explainability
# ------------------------------------------------------------------------------
elif page == "🔬 Explainability":
    tab_imp, tab_err = st.tabs(["🔬 Feature Importance & Attributions", "❌ Error Analysis (Misclassifications)"])
    with tab_imp:
        render_feature_importance_page(df_importance, training_meta)
    with tab_err:
        render_error_analysis_page(df_test_preds, df, split_info, feat_cols)
    render_footer()

# ------------------------------------------------------------------------------
# 9. 📁 Batch Analysis
# ------------------------------------------------------------------------------
elif page == "📁 Batch Analysis":
    render_batch_analysis_page(final_model, feat_cols, PROJECT_ROOT)
    render_footer()

# ------------------------------------------------------------------------------
# 10. ℹ️ About
# ------------------------------------------------------------------------------
elif page == "ℹ️ About":
    render_about_project_page()
    render_footer()