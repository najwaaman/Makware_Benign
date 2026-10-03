# Malware Classification Using Machine Learning

> **PE-Feature Based Static Malware Detection & Interactive Web System**

---

## 📌 Problem Statement

Traditional signature-based antivirus solutions often struggle against rapid malware mutation, polymorphic packing, and zero-day variants. Dynamic execution sandboxing provides behavioral insights but is resource-intensive, slow, and prone to sandbox evasion techniques. 

Static analysis of Portable Executable (PE) headers offers an ultra-fast, safe, and computationally efficient first line of defense. By inspecting header structural properties, section entropy, virtual memory allocations, and linker metadata, machine learning classifiers can accurately differentiate between benign software and malicious executables prior to execution.

---

## 🎯 Project Objective

To develop a machine-learning based system that classifies PE-file feature data as **Malware** or **Benign** using static header metadata, featuring a robust multi-stage feature engineering pipeline and an interactive Streamlit analytical dashboard.

---

## 📊 Dataset & PE Features

- **Total Samples:** `19,611` executable records
- **Total Columns:** `79` columns (1 identifier `Hash_md5_Name`, 77 numeric PE header predictors, 1 binary target `Malware`)
- **Target Distribution:**
  - **Malware (Class 1):** `14,599` samples (**74.44%**)
  - **Benign (Class 0):** `5,012` samples (**25.56%**)
- **Data Integrity:** `0` missing values across all 79 columns.
- **Key PE Header Feature Domains:**
  - **DOS & COFF Header:** `e_magic`, `Machine`, `NumberOfSections`, `TimeDateStamp`, `Characteristics`, `PointerToSymbolTable`
  - **Optional Header:** `Magic`, `MajorLinkerVersion`, `SizeOfCode`, `SizeOfImage`, `ImageBase`, `Subsystem`, `DllCharacteristics`, `SizeOfStackReserve`, `CheckSum`
  - **Section Properties & Entropy:** `SectionMaxEntropy`, `SectionMinEntropy`, `SectionMaxRawsize`, `SectionMinRawsize`, `SectionMaxVirtualsize`, `SuspiciousNameSection`
  - **Imports & Exports:** `DirectoryEntryImport`, `DirectoryEntryImportSize`, `DirectoryEntryExport`, `SuspiciousImportFunctions`

---

## 🧹 Preprocessing & Leakage Prevention

1. **Identifier Exclusion:** The cryptographic hash (`Hash_md5_Name`) is strictly excluded from all modeling stages.
2. **Stratified Partitioning (80/20):**
   - **Training Set (80%):** `15,688` samples (11,679 Malware, 4,009 Benign)
   - **Untouched Test Set (20%):** `3,923` samples (2,920 Malware, 1,003 Benign)
   - Stored in `models/split_indices.json` to ensure exact reproducibility and zero data leakage.
3. **Missing Value & Duplicate Audit:** Zero missing cells detected; 2,975 redundant feature-vector duplicates and 4 conflicting label patterns identified and audited.

---

## 🧠 Domain Feature Engineering

Five domain-specific PE structural ratios and spread indicators are created via `src/pipeline.py:FeatureEngineer` with safe division:

| Engineered Feature | Mathematical Formula | Domain Rationale |
| :--- | :--- | :--- |
| `CodeToImageRatio` | $\frac{\text{SizeOfCode}}{\text{SizeOfImage} + 1}$ | Proportion of mapped memory occupied by code; low ratios signal packed payloads. |
| `InitializedDataRatio` | $\frac{\text{SizeOfInitializedData}}{\text{SizeOfImage} + 1}$ | Density of initialized global data; oversized data sections often conceal shellcode. |
| `SectionRawSizeRange` | $\text{SectionMaxRawsize} - \text{SectionMinRawsize}$ | Spread between largest and smallest raw disk section dimensions. |
| `SectionVirtualSizeRange` | $\text{SectionMaxVirtualsize} - \text{SectionMinVirtualsize}$ | Spread between maximum and minimum memory virtual section dimensions. |
| `SectionEntropyRange` | $\text{SectionMaxEntropy} - \text{SectionMinEntropy}$ | Entropy disparity between packed/encrypted sections and plain code sections. |

---

## 🎯 Multi-Stage Feature Selection Funnel

Features are filtered strictly inside the training fold:

```
[Raw Features: 77]
       │
       ▼ (Feature Engineering: +5 domain features)
[Expanded Features: 82]
       │
       ▼ (VarianceThreshold: 8 zero-variance constant features dropped)
[Post-Variance Features: 74]
       │
       ▼ (CorrelationFilter: 6 collinear features with |r| > 0.95 dropped)
[Post-Correlation Features: 68]
       │
       ▼ (SelectFromModel: Balanced Random Forest feature selection)
[Final Selected Features: 16]
```

**Final Selected Predictors (16):**
`TimeDateStamp`, `Characteristics`, `MajorLinkerVersion`, `SizeOfInitializedData`, `ImageBase`, `MajorOperatingSystemVersion`, `MinorOperatingSystemVersion`, `MinorImageVersion`, `MajorSubsystemVersion`, `MinorSubsystemVersion`, `CheckSum`, `Subsystem`, `DllCharacteristics`, `SizeOfStackReserve`, `DirectoryEntryImportSize`, `DirectoryEntryExport`.

---

## 🤖 Algorithms & Model Evaluation

Candidate pipelines evaluated with **5-fold Stratified Cross-Validation** on the training partition:

1. **Logistic Regression** (with `StandardScaler`, `class_weight='balanced'`)
2. **Decision Tree** (`max_depth=12`, `class_weight='balanced'`)
3. **Random Forest** (`n_estimators=100`, `max_depth=15`, `class_weight='balanced'`)
4. **HistGradientBoosting** (`class_weight='balanced'`, `max_iter=100`)

### Performance Benchmark Table (Untouched Test Set, $N=3,923$)

| Model | 5-Fold CV F1 (Mean ± Std) | CV ROC-AUC | Test Accuracy | Test Precision | Test Recall | Test F1 Score | Test ROC-AUC | Test PR-AUC | Test MCC | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **HistGradientBoosting** | **0.9947 ± 0.0016** | **0.9971** | **99.21%** | **0.9912** | **0.9983** | **0.9947** | **0.9967** | **0.9985** | **0.9792** | **⭐ WINNING MODEL** |
| **Random Forest** | 0.9945 ± 0.0015 | 0.9975 | 99.16% | 0.9905 | 0.9983 | 0.9944 | 0.9974 | 0.9989 | 0.9778 | Candidate |
| **Decision Tree** | 0.9925 ± 0.0014 | 0.9857 | 98.70% | 0.9901 | 0.9925 | 0.9913 | 0.9865 | 0.9915 | 0.9658 | Candidate |
| **Logistic Regression** | 0.9549 ± 0.0075 | 0.9657 | 93.12% | 0.9763 | 0.9301 | 0.9526 | 0.9559 | 0.9783 | 0.8302 | Candidate |

- **Selection Criterion:** Highest mean 5-fold Stratified CV F1 score on training set (tie-break: CV ROC-AUC).
- **Final Confusion Matrix (HistGradientBoosting):**
  - **True Positives (TP):** 2,915
  - **True Negatives (TN):** 977
  - **False Positives (FP):** 26
  - **False Negatives (FN):** 5 (Evading Malware Rate = 0.17%)

---

## 📁 Project Structure

```text
malware_classification/
├── data/
│   └── Malware-Benign.csv               # Raw static PE feature dataset
├── src/
│   ├── __init__.py
│   └── pipeline.py                      # Reusable transformers, loader, summary & metrics
├── models/
│   ├── final_model.pkl                  # Full winning scikit-learn pipeline
│   ├── feature_selector.pkl             # Fitted SelectFromModel transformer
│   ├── split_indices.json               # Disjoint 80/20 train/test sample indices
│   ├── feature_columns.json             # 77 raw predictor column names in order
│   ├── selected_features.json           # Funnel tracking & final 16 feature names
│   ├── model_metrics.json               # CV results & test evaluation metrics
│   ├── feature_importance.csv           # Permutation importance scores
│   ├── test_predictions.csv            # Test set predictions & probabilities
│   ├── roc_data.json                    # Curve coordinates for ROC & PR curves
│   └── training_metadata.json           # Environment & library versions
├── outputs/
│   ├── confusion_matrix/                # Confusion matrix plots (PNG)
│   ├── roc_curves/                      # ROC & Precision-Recall curve plots (PNG)
│   ├── feature_importance/              # Feature importance horizontal bar charts (PNG)
│   └── reports/                         # Run summaries & comparison CSVs
├── dashboard/
│   ├── __init__.py
│   ├── app.py                           # Main Streamlit dashboard application
│   ├── eda_view.py                      # Exploratory Data Analysis page views
│   ├── models_view.py                   # Model training, evaluation & error views
│   ├── prediction_view.py               # Single sample & batch CSV inference engine
│   └── reports_view.py                  # Downloads & Project documentation views
├── tests/
│   ├── check_data.py                    # Dataset validation script
│   ├── test_components.py               # Model & inference test suite
│   └── smoke_test.py                    # End-to-end smoke test suite (AppTest)
├── requirements.txt                     # Minimum Python dependencies
└── README.md                            # Comprehensive project documentation
```

---

## 💻 Installation & Setup

### 1. Clone or Open the Workspace
```powershell
cd C:\Users\HP\.gemini\antigravity\scratch\malware_classification
```

### 2. Install Required Dependencies
```powershell
pip install -r requirements.txt
```

---

## 🚀 How to Run

### Step 1: Run the Training Pipeline
Train all candidate pipelines, perform 5-fold CV, and save artifacts:
```powershell
python train_model.py
```

### Step 2: Run the Smoke Test Suite
Verify dataset integrity, model serialization, and dashboard UI navigation:
```powershell
python tests/smoke_test.py
```

### Step 3: Launch the Streamlit Dashboard
Launch the interactive web application:
```powershell
python -m streamlit run dashboard/app.py
```
Open your browser at: `http://localhost:8501`

---

## ⚠️ Limitations & Security Notice

1. **Static Analysis Boundary:** The model evaluates PE header structural metadata. It does not analyze runtime memory injection, dynamic API call sequences, or network traffic.
2. **Dataset-Specific Generalization:** While demonstrating 99.21% test accuracy on this benchmark, performance may vary against completely novel zero-day malware families utilizing header evasion techniques.
3. **Operational Usage:** This machine learning classifier is designed as a fast, automated triage filter to accompany dynamic sandboxing and signature verification engines.

---

## 🔮 Future Enhancements

- **Dynamic Sandbox Feature Fusion:** Integration of Cuckoo / CAPE sandbox behavioral logs (API call n-grams, network domains).
- **Deep Byte-Level Embeddings:** Incorporating 1D CNN / Transformer models (e.g. MalConv) directly on raw PE byte streams.
- **Explainability Integrations:** Adding SHAP (SHapley Additive exPlanations) force plots for single sample inference explainability.
- **Automated PE Extraction Engine:** Allowing raw `.exe` / `.dll` file upload with real-time header parsing via `pefile`.

---

## 🎓 Academic Submission

- **Author:** Najwa MD A
- **Registration Number:** `210425243165`
- **Course:** Malware Classification Using Machine Learning (College Capstone Project)