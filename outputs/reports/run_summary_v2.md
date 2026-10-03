# Malware Sentinel: End-to-End System Run Summary (v2.0)

## 1. Final Model Architecture
- **Classifier Selected:** `HistGradientBoostingClassifier`
- **Model Selection Criterion:** Highest mean 5-fold Stratified Cross-Validation F1-score on the training set (with CV ROC-AUC tie-breaker).
- **Class Balancing:** `class_weight='balanced'` enabled across all candidate models to account for the ~3:1 malware-to-benign class ratio.
- **Pipeline Stages (Strict Data Leakage Prevention):**
  1. `FeatureEngineer`: Computes 5 domain-specific PE ratio and entropy spread metrics (`CodeToImageRatio`, `InitializedDataRatio`, `SectionRawSizeRange`, `SectionVirtualSizeRange`, `SectionEntropyRange`) using safe division.
  2. `VarianceThreshold(threshold=0.0)`: Drops zero-variance constant features (14 features removed).
  3. `CorrelationFilter(threshold=0.95)`: Removes redundant collinear predictors with $|r| > 0.95$ (25 features removed).
  4. `SelectFromModel(RandomForestClassifier, random_state=42)`: Retains the top 16 most discriminative features based on Gini importance.
  5. `HistGradientBoostingClassifier(random_state=42)`: Tree-based gradient boosting estimator.

---

## 2. Model Performance Benchmarks (Out-of-Sample Test Set)

Evaluated on the **20% untouched test set** (3,923 samples: 2,920 Malware, 1,003 Benign):

| Metric | Score | Evaluation Context |
| :--- | :--- | :--- |
| **Accuracy** | **99.21%** (0.9921) | Overall correct classification rate |
| **Precision** | **99.12%** (0.9912) | Correct positive detections out of all flagged alerts |
| **Recall (Sensitivity)** | **99.83%** (0.9983) | True positive detection rate (only 5 false negatives) |
| **F1-Score** | **99.47%** (0.9947) | Harmonic mean of Precision and Recall |
| **ROC-AUC** | **99.67%** (0.9967) | Area under the Receiver Operating Characteristic curve |
| **PR-AUC** | **99.89%** (0.9989) | Area under the Precision-Recall curve |
| **Matthews Corr (MCC)** | **0.9786** (0.9786) | Robust metric accounting for class imbalance |

---

## 3. Selected Feature Count & Schema Breakdown
- **Raw Features in Dataset:** 77 numeric predictors (excluding MD5 identifier and target).
- **Post Feature Engineering:** 82 total features (77 raw + 5 engineered).
- **Post Variance Threshold:** 68 features (14 constant columns removed).
- **Post Correlation Filter:** 43 features (25 collinear columns removed).
- **Final Selected Features (`SelectFromModel`):** **16 features**
  - `Characteristics`, `TimeDateStamp`, `MajorLinkerVersion`, `MinorLinkerVersion`, `SizeOfCode`, `SizeOfInitializedData`, `ImageBase`, `MajorOperatingSystemVersion`, `MinorOperatingSystemVersion`, `MajorSubsystemVersion`, `CheckSum`, `Subsystem`, `DllCharacteristics`, `SizeOfStackReserve`, `DirectoryEntryExport`, `SectionMinEntropy`.

---

## 4. Feature Extraction & Compatibility Audit

### A. Direct Header Attributes (Extracted via `pefile`):
- **DOS Header (17):** `e_magic`, `e_cblp`, `e_cp`, `e_crlc`, `e_cparhdr`, `e_minalloc`, `e_maxalloc`, `e_ss`, `e_sp`, `e_csum`, `e_ip`, `e_cs`, `e_lfarlc`, `e_ovno`, `e_oemid`, `e_oeminfo`, `e_lfanew`.
- **File / COFF Header (7):** `Machine`, `NumberOfSections`, `TimeDateStamp`, `PointerToSymbolTable`, `NumberOfSymbols`, `SizeOfOptionalHeader`, `Characteristics`.
- **Optional Header (23):** `Magic`, `MajorLinkerVersion`, `MinorLinkerVersion`, `SizeOfCode`, `SizeOfInitializedData`, `SizeOfUninitializedData`, `AddressOfEntryPoint`, `BaseOfCode`, `ImageBase`, `SectionAlignment`, `FileAlignment`, `MajorOperatingSystemVersion`, `MinorOperatingSystemVersion`, `MajorImageVersion`, `MinorImageVersion`, `MajorSubsystemVersion`, `MinorSubsystemVersion`, `SizeOfHeaders`, `CheckSum`, `SizeOfImage`, `Subsystem`, `DllCharacteristics`, `SizeOfStackReserve`, `SizeOfStackCommit`, `SizeOfHeapReserve`, `SizeOfHeapCommit`, `LoaderFlags`, `NumberOfRvaAndSizes`.
- **Data Directories (5):** `ImageDirectoryEntryExport`, `ImageDirectoryEntryImport`, `ImageDirectoryEntryResource`, `ImageDirectoryEntryException`, `ImageDirectoryEntrySecurity`.
- **Directory Counts (2):** `DirectoryEntryImport`, `DirectoryEntryImportSize`, `DirectoryEntryExport`.

### B. Reconstructed Heuristic & Computed Approximations:
- `SuspiciousImportFunctions`: Heuristic matching of dangerous Windows API keywords (injection, evasion, memory protection, keylogging) from `DIRECTORY_ENTRY_IMPORT`.
- `SuspiciousNameSection`: Heuristic inspection of non-standard, obfuscated, or known packer section names (UPX, ASPack, Themida, VMProtect).
- `SectionsLength`: Number of section headers present.
- `SectionMinEntropy`, `SectionMaxPhysical`, `SectionMaxVirtual`, `SectionMaxPointerData`, `SectionMaxChar`: Computed directly from raw section tables.

### C. Dataset Constant Columns (Zeroed to match CSV schema convention):
- `SectionMaxEntropy`, `SectionMaxRawsize`, `SectionMaxVirtualsize`, `SectionMinPhysical`, `SectionMinVirtual`, `SectionMinPointerData`, `SectionMainChar`.

### D. Unextractable Features:
- **0 features unextractable.** All 77 numeric features required by the pipeline are extracted or aligned to 100% schema completeness.

---

## 5. Model Explainability Mechanism
- **Method Used:** `shap.TreeExplainer` on the fitted `HistGradientBoostingClassifier` estimator.
- **Transformation Pipeline:** Raw 77-feature inputs are first transformed through `pipeline.steps[:-1]` (`FeatureEngineer` $\rightarrow$ `VarianceThreshold` $\rightarrow$ `CorrelationFilter` $\rightarrow$ `SelectFromModel`) before computing Shapley values.
- **Direction & Attribution:**
  - Positive SHAP value $\rightarrow$ Pushes prediction **Toward Malware**.
  - Negative SHAP value $\rightarrow$ Pushes prediction **Toward Benign**.
- **Magnitude Buckets:** Relative impact normalized to `High` ($\ge 50\%$), `Medium` ($\ge 20\%$), or `Low` ($< 20\%$).
- **Disclaimers:** Automatically appends caution tags to reconstructed heuristic features and generates human-readable influence summaries.

---

## 6. How to Run the Application

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. (Optional) Retrain all model pipelines and generate artifacts
python train_model.py

# 3. Launch the Streamlit dashboard
streamlit run dashboard/app.py
```

---

## 7. Quality Assurance & Verification Summary

| Test Category | Test File / Command | Result | Notes |
| :--- | :--- | :--- | :--- |
| **Train/Test Integrity** | `tests/smoke_test.py` (Check 1) | **PASS** | Strict disjoint sets (15,688 / 3,923) |
| **Feature Schema Alignment** | `tests/smoke_test.py` (Check 2) | **PASS** | Exact 77-feature ordering verified |
| **Model Inference** | `tests/smoke_test.py` (Check 3) | **PASS** | Correct probability ranges & summation |
| **Streamlit UI Navigation** | `tests/smoke_test.py` (Check 4) | **PASS** | All 10 pages render with 0 exceptions |
| **Live PE Extraction** | `tests/test_extractor.py` | **PASS** | Tested on `notepad.exe`, `cmd.exe`, `calc.exe` |
| **Corrupt File Handling** | `tests/test_extractor.py` | **PASS** | Clean `PEExtractionError`, 0 tracebacks |
| **SHAP Explainability** | `tests/test_explain.py` | **PASS** | Accurate direction & magnitude bucketing |
| **Detection Page Pipeline** | `tests/test_detection_flow.py` | **PASS** | End-to-end extraction, inference & summary |
| **Full Subsystem Suite** | `tests/test_full_suite.py` | **PASS** | 8/8 subsystems passed with zero errors |
