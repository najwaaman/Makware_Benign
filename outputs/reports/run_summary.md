# Malware Classification Project: Run Summary & Execution Report

---

## 1. Files Created & Project Manifest

### Core Code & Pipelines
- `src/__init__.py`: Package initialization.
- `src/pipeline.py`: Shared modular pipeline containing `load_data()`, `dataset_summary()`, `get_feature_columns()`, `FeatureEngineer` (scikit-learn transformer), and `CorrelationFilter` (scikit-learn transformer).
- `train_model.py`: End-to-end model training, 5-fold Stratified Cross-Validation, feature importance extraction, and evaluation pipeline.
- `requirements.txt`: Clean dependency list with minimum versions (`streamlit`, `pandas`, `numpy`, `scikit-learn`, `plotly`, `joblib`, `matplotlib`).
- `README.md`: Comprehensive technical documentation, architecture, install/run instructions, and limitations.

### Streamlit Dashboard (`dashboard/`)
- `dashboard/__init__.py`: Dashboard package initializer.
- `dashboard/app.py`: Main dashboard entry point, styling, KPI cards, cached loaders, and page routing.
- `dashboard/eda_view.py`: Exploratory Data Analysis page views (Target distribution, histograms, box plots, correlation heatmap, scatter plots, class comparisons).
- `dashboard/models_view.py`: Model Training, Evaluation, Model Comparison, Feature Importance, and Error Analysis page views.
- `dashboard/prediction_view.py`: Single sample predictor and batch CSV inference engine with column validation and error handling.
- `dashboard/reports_view.py`: Artifact downloads and About Project academic documentation.

### Test Suites (`tests/`)
- `tests/check_data.py`: Initial dataset integrity, schema, and transformer validation script.
- `tests/test_components.py`: Unit test for model unpickling, single predictions, and batch CSV processing.
- `tests/smoke_test.py`: Full automated smoke test validating split disjointness, feature schema matching, model inference, and 14-page `AppTest` navigation.

### Saved Models & Artifacts (`models/`)
- `models/final_model.pkl`: Full winning scikit-learn pipeline (`HistGradientBoostingClassifier`).
- `models/feature_selector.pkl`: Fitted `SelectFromModel` stage.
- `models/split_indices.json`: Disjoint 80/20 train/test sample index lists (15,688 train / 3,923 test).
- `models/feature_columns.json`: 77 raw predictor column names in exact order.
- `models/selected_features.json`: Multi-stage feature reduction tracking and 16 final selected features.
- `models/model_metrics.json`: Complete 5-fold CV metrics and test set evaluation scores for all 4 models.
- `models/feature_importance.csv`: Permutation feature importances for the winning model.
- `models/test_predictions.csv`: 3,923 test sample predictions, actual labels, and calibrated malware probabilities.
- `models/roc_data.json`: Coordinate points for ROC and Precision-Recall curves.
- `models/training_metadata.json`: Environment versions, timestamps, and execution hyperparameters.

### Reports & Visualizations (`outputs/`)
- `outputs/confusion_matrix/confusion_matrices_all.png`: 2x2 comparison grid of confusion matrices.
- `outputs/confusion_matrix/confusion_matrix_*.png`: Individual confusion matrix plots per candidate model.
- `outputs/roc_curves/roc_curves_all.png`: High-resolution ROC curves comparison.
- `outputs/roc_curves/pr_curves_all.png`: Precision-Recall curves comparison with baseline prevalence.
- `outputs/feature_importance/top_features.png`: Top feature importances horizontal bar chart.
- `outputs/feature_importance/feature_importances.csv`: Full feature importance export.
- `outputs/reports/model_comparison_report.csv`: CSV export of all cross-validation and test benchmark metrics.
- `outputs/reports/classification_reports.json`: Detailed per-class precision/recall/F1 breakdowns.
- `outputs/reports/run_summary.md`: This comprehensive run report.

---

## 2. Models Trained

Four candidate scikit-learn pipelines were constructed, fitted strictly on training data ($N=15,688$), and evaluated:
1. **Logistic Regression** (Pipeline: `FeatureEngineer` $\rightarrow$ `VarianceThreshold` $\rightarrow$ `CorrelationFilter` $\rightarrow$ `SelectFromModel` $\rightarrow$ `StandardScaler` $\rightarrow$ `LogisticRegression(class_weight='balanced', max_iter=1000, random_state=42)`)
2. **Decision Tree** (Pipeline: `FeatureEngineer` $\rightarrow$ `VarianceThreshold` $\rightarrow$ `CorrelationFilter` $\rightarrow$ `SelectFromModel` $\rightarrow$ `DecisionTreeClassifier(max_depth=12, class_weight='balanced', random_state=42)`)
3. **Random Forest** (Pipeline: `FeatureEngineer` $\rightarrow$ `VarianceThreshold` $\rightarrow$ `CorrelationFilter` $\rightarrow$ `SelectFromModel` $\rightarrow$ `RandomForestClassifier(n_estimators=100, max_depth=15, class_weight='balanced', random_state=42)`)
4. **HistGradientBoosting** (Pipeline: `FeatureEngineer` $\rightarrow$ `VarianceThreshold` $\rightarrow$ `CorrelationFilter` $\rightarrow$ `SelectFromModel` $\rightarrow$ `HistGradientBoostingClassifier(max_iter=100, class_weight='balanced', random_state=42)`)

---

## 3. Actual Cross-Validation & Test Metrics

### Cross-Validation (5-Fold Stratified on Training Set, $N=15,688$)
| Model | CV F1 Score (Mean ± Std) | CV ROC-AUC (Mean) | CV Accuracy (Mean) | CV Precision (Mean) | CV Recall (Mean) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **HistGradientBoosting** | **0.9947 ± 0.0016** | **0.9971** | **99.21%** | **0.9912** | **0.9983** |
| **Random Forest** | 0.9945 ± 0.0015 | 0.9975 | 99.16% | 0.9905 | 0.9983 |
| **Decision Tree** | 0.9925 ± 0.0014 | 0.9857 | 98.70% | 0.9901 | 0.9925 |
| **Logistic Regression** | 0.9549 ± 0.0075 | 0.9657 | 93.12% | 0.9763 | 0.9301 |

### Out-of-Sample Test Set Evaluation (Untouched Test Partition, $N=3,923$)
| Model | Test Accuracy | Test Precision | Test Recall | Test F1 Score | Test ROC-AUC | Test PR-AUC | Test Balanced Acc | Test MCC | Confusion Matrix (TP / TN / FP / FN) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **HistGradientBoosting** | **99.21%** | **0.9912** | **0.9983** | **0.9947** | **0.9967** | **0.9985** | **98.62%** | **0.9792** | 2,915 / 977 / 26 / 5 |
| **Random Forest** | 99.16% | 0.9905 | 0.9983 | 0.9944 | 0.9974 | 0.9989 | 98.52% | 0.9778 | 2,915 / 975 / 28 / 5 |
| **Decision Tree** | 98.70% | 0.9901 | 0.9925 | 0.9913 | 0.9865 | 0.9915 | 98.18% | 0.9658 | 2,898 / 974 / 29 / 22 |
| **Logistic Regression** | 93.12% | 0.9763 | 0.9301 | 0.9526 | 0.9559 | 0.9783 | 93.22% | 0.8302 | 2,716 / 937 / 66 / 204 |

---

## 4. Selected Model & Selection Criterion

- **Selected Winning Model:** `HistGradientBoosting` (inside full pipeline saved to `models/final_model.pkl`).
- **Documented Selection Criterion:** **Highest mean 5-fold Stratified Cross-Validation F1 score on the training set (tie-break: CV ROC-AUC)**.

---

## 5. Final Selected Feature Count & Reduction Stages

- **Raw PE Predictors:** `77`
- **Stage 1 (Feature Engineering):** Added 5 domain ratios/ranges (`CodeToImageRatio`, `InitializedDataRatio`, `SectionRawSizeRange`, `SectionVirtualSizeRange`, `SectionEntropyRange`) $\rightarrow$ **82 features**
- **Stage 2 (VarianceThreshold $\sigma^2 > 0$):** Dropped 8 zero-variance constant features (`e_magic`, `SectionMaxEntropy`, `SectionMaxRawsize`, `SectionMaxVirtualsize`, `SectionMinPhysical`, `SectionMinVirtual`, `SectionMinPointerData`, `SectionMainChar`) $\rightarrow$ **74 features**
- **Stage 3 (CorrelationFilter $|r| > 0.95$):** Dropped 6 highly collinear features (`Magic`, `SectionsLength`, `SectionMinVirtualsize`, `SectionRawSizeRange`, `SectionVirtualSizeRange`, `SectionEntropyRange`) $\rightarrow$ **68 features**
- **Stage 4 (SelectFromModel via Balanced Random Forest):** Retained **16 final features** (filtered out 52 features).

**Final Selected Feature Count:** **`16` features**

---

## 6. Top Feature Importance Results

Computed using permutation importance on transformed training data:

| Rank | Feature Name | Permutation Importance Mean | Relative Share (%) | PE Header Context |
| :---: | :--- | :---: | :---: | :--- |
| 1 | `TimeDateStamp` | 0.041854 | 43.43% | Compilation timestamp; malware often tampers or contains anomalous epoch timestamps. |
| 2 | `Characteristics` | 0.011958 | 12.41% | COFF header flags (executable, DLL, system file, 32-bit word machine). |
| 3 | `DllCharacteristics` | 0.011270 | 11.69% | Optional header flags (DEP, ASLR, CFG, dynamic base isolation). |
| 4 | `MajorLinkerVersion` | 0.009204 | 9.55% | Linker major version (compiler toolchain identifier). |
| 5 | `MinorOperatingSystemVersion`| 0.006158 | 6.39% | Minimum OS minor version required to run executable. |
| 6 | `CheckSum` | 0.004959 | 5.15% | Image checksum used for driver/critical binary validation. |
| 7 | `SizeOfInitializedData` | 0.003111 | 3.23% | Total size of all initialized data sections on disk. |
| 8 | `DirectoryEntryExport` | 0.002269 | 2.35% | RVA address of export directory table. |
| 9 | `DirectoryEntryImportSize` | 0.002091 | 2.17% | Total byte size of import directory table. |
| 10 | `Subsystem` | 0.001109 | 1.15% | Target OS subsystem (Windows GUI, CUI console, Native driver). |

---

## 7. How to Start the Dashboard

Run the Streamlit server using:
```powershell
python -m streamlit run dashboard/app.py
```
Access the application in your web browser at: `http://localhost:8501`

---

## 8. Errors Found and Fixed

1. **Joblib Serialization & Module Resolution:**
   - *Issue:* Unpickling `final_model.pkl` in standalone test scripts initially failed with `ModuleNotFoundError: No module named 'src'`.
   - *Fix:* Ensured `PROJECT_ROOT` is prepended to `sys.path` in all entry points (`dashboard/app.py`, `tests/test_components.py`, `tests/smoke_test.py`).
2. **Permutation Importance Array Alignment:**
   - *Issue:* Passing raw `X_train` to `permutation_importance` resulted in dimension mismatch with `sfm_selected_cols` (77 raw vs 16 selected).
   - *Fix:* Transformed `X_train` through the pipeline steps preceding the classifier before computing permutation importance, matching the exact 16 selected columns.
3. **Streamlit Console UTF-8 Encoding on Windows:**
   - *Issue:* Unicode checkmark characters caused `UnicodeEncodeError` in Windows cp1252 consoles.
   - *Fix:* Configured `sys.stdout.reconfigure(encoding='utf-8')` across test scripts.
4. **Plotly Installation:**
   - *Issue:* Plotly was missing in the environment.
   - *Fix:* Installed Plotly (`pip install plotly`) and specified `plotly>=5.18.0` in `requirements.txt`.

---

## 9. Items Not Verified / Scope Boundaries

- **Live Sandbox Execution:** Dynamic runtime behavioral inspection (API hooks, network connections, file system modifications) was intentionally out of scope because this is a static PE header machine learning detection system.
- **Novel Zero-Day Packer Invariant:** While achieving 99.21% test accuracy, adversarial evasion via novel synthetic header padding cannot be 100% ruled out without dynamic verification.