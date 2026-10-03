"""
PE Feature Extractor Module.
Safe static analysis of Portable Executable (PE) binaries via pefile.
Extracts all 77 numeric PE header features required by the Malware Classification pipeline.
"""

import hashlib
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

import numpy as np
import pandas as pd
import pefile

# Project Root & Feature Columns
PROJECT_ROOT = Path(__file__).resolve().parent.parent
FEATURE_COLUMNS_PATH = PROJECT_ROOT / "models" / "feature_columns.json"

# Known suspicious API keywords for heuristic approximation
SUSPICIOUS_API_KEYWORDS = {
    # Process Injection & Memory Manipulation
    "virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
    "writeprocessmemory", "readprocessmemory", "createremotethread", "ntcreatethreadex",
    "queueuserapc", "setthreadcontext", "getthreadcontext", "resumethread",
    # Process Creation & Execution
    "createprocessa", "createprocessw", "winexec", "shellexecutea", "shellexecutew",
    "shellexecuteexa", "shellexecuteexw", "openprocess",
    # Dynamic Loading & Hooking
    "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw",
    "getprocaddress", "setwindowshookexa", "setwindowshookexw", "unhookwindowshookex",
    # Anti-Debugging & Evasion
    "isdebuggerpresent", "checkremotedebuggerpresent", "outputdebugstringa",
    "outputdebugstringw", "ntqueryinformationprocess", "findwindowa", "findwindoww",
    # Persistence & Registry
    "regopenkeyexa", "regopenkeyexw", "regsetvalueexa", "regsetvalueexw",
    "regcreatekeyexa", "regcreatekeyexw",
    # Networking & Downloading
    "urldownloadtofilea", "urldownloadtofilew", "internetopena", "internetopenw",
    "internetconnecta", "internetconnectw", "httpopenrequesta", "httpopenrequestw",
    "httpsendrequesta", "httpsendrequestw", "wsastartup", "connect", "send", "recv",
    # Keylogging & Input Capture
    "getasynckeystate", "getkeystate", "getkeyboardstate", "registerhotkey",
    # File Manipulation / Droppers
    "createfilea", "createfilew", "writefile", "deletefilea", "deletefilew",
    "copyfilea", "copyfilew",
}

# Standard non-suspicious section names
STANDARD_SECTION_NAMES = {
    ".text", ".data", ".rdata", ".idata", ".edata", ".rsrc", ".reloc",
    ".bss", ".tls", ".pdata", ".debug", ".gfids", ".giats", ".didat",
    "code", "data", "text", "rdata", "bss",
}

# Known packer / obfuscated section signatures
SUSPICIOUS_SECTION_PATTERNS = {
    "upx", "aspack", "mpress", "themida", "vmp", "enigma", "pack",
    "packed", "fsg", "nsp", "pecompact", "petite", "mew", "wwpack",
}


class PEExtractionError(Exception):
    """Custom exception raised when PE extraction fails or file is corrupt/non-PE."""
    pass


def load_expected_feature_columns() -> List[str]:
    """Load the ordered list of 77 feature names expected by the model pipeline."""
    if FEATURE_COLUMNS_PATH.exists():
        with open(FEATURE_COLUMNS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    raise FileNotFoundError(f"Feature columns schema not found at {FEATURE_COLUMNS_PATH}")


def compute_hashes(file_bytes: bytes) -> Dict[str, str]:
    """Compute cryptographic hashes of file bytes (for display/identification only)."""
    return {
        "md5": hashlib.md5(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
        "size_bytes": len(file_bytes),
    }


def extract_features(file_bytes: bytes) -> Dict[str, Any]:
    """
    Extract all 77 numeric PE header features from raw binary bytes.
    
    Args:
        file_bytes: Raw bytes of the executable binary.
        
    Returns:
        Dict[str, Any] containing:
            - 'features': Dict[str, float] with all 77 raw feature values.
            - 'hashes': Dict[str, str] with MD5, SHA-1, SHA-256 hashes.
            - 'metadata': General PE properties (section names, imports, architecture).
            
    Raises:
        PEExtractionError: If the bytes do not represent a valid PE file or parsing fails.
    """
    if not isinstance(file_bytes, (bytes, bytearray)):
        raise PEExtractionError("Input must be a valid bytes or bytearray object.")

    if len(file_bytes) < 64:
        raise PEExtractionError("File size is too small to contain a valid PE DOS header (< 64 bytes).")

    # Safe parsing via pefile - never executes the binary
    try:
        pe = pefile.PE(data=file_bytes, fast_load=False)
    except pefile.PEFormatError as e:
        raise PEExtractionError(f"Invalid or corrupted PE binary format: {e}")
    except Exception as e:
        raise PEExtractionError(f"Unexpected error parsing PE structure: {e}")

    try:
        features: Dict[str, float] = {}

        # ----------------------------------------------------------------------
        # 1. DOS HEADER (DIRECT)
        # ----------------------------------------------------------------------
        dos = pe.DOS_HEADER if hasattr(pe, "DOS_HEADER") else None
        features["e_magic"] = float(getattr(dos, "e_magic", 23117))
        features["e_cblp"] = float(getattr(dos, "e_cblp", 0))
        features["e_cp"] = float(getattr(dos, "e_cp", 0))
        features["e_crlc"] = float(getattr(dos, "e_crlc", 0))
        features["e_cparhdr"] = float(getattr(dos, "e_cparhdr", 0))
        features["e_minalloc"] = float(getattr(dos, "e_minalloc", 0))
        features["e_maxalloc"] = float(getattr(dos, "e_maxalloc", 0))
        features["e_ss"] = float(getattr(dos, "e_ss", 0))
        features["e_sp"] = float(getattr(dos, "e_sp", 0))
        features["e_csum"] = float(getattr(dos, "e_csum", 0))
        features["e_ip"] = float(getattr(dos, "e_ip", 0))
        features["e_cs"] = float(getattr(dos, "e_cs", 0))
        features["e_lfarlc"] = float(getattr(dos, "e_lfarlc", 0))
        features["e_ovno"] = float(getattr(dos, "e_ovno", 0))
        features["e_oemid"] = float(getattr(dos, "e_oemid", 0))
        features["e_oeminfo"] = float(getattr(dos, "e_oeminfo", 0))
        features["e_lfanew"] = float(getattr(dos, "e_lfanew", 0))

        # ----------------------------------------------------------------------
        # 2. FILE / COFF HEADER (DIRECT)
        # ----------------------------------------------------------------------
        fh = pe.FILE_HEADER if hasattr(pe, "FILE_HEADER") else None
        features["Machine"] = float(getattr(fh, "Machine", 0))
        features["NumberOfSections"] = float(getattr(fh, "NumberOfSections", len(pe.sections)))
        features["TimeDateStamp"] = float(getattr(fh, "TimeDateStamp", 0))
        features["PointerToSymbolTable"] = float(getattr(fh, "PointerToSymbolTable", 0))
        features["NumberOfSymbols"] = float(getattr(fh, "NumberOfSymbols", 0))
        features["SizeOfOptionalHeader"] = float(getattr(fh, "SizeOfOptionalHeader", 0))
        features["Characteristics"] = float(getattr(fh, "Characteristics", 0))

        # ----------------------------------------------------------------------
        # 3. OPTIONAL HEADER (DIRECT)
        # ----------------------------------------------------------------------
        opt = pe.OPTIONAL_HEADER if hasattr(pe, "OPTIONAL_HEADER") else None
        features["Magic"] = float(getattr(opt, "Magic", 0))
        features["MajorLinkerVersion"] = float(getattr(opt, "MajorLinkerVersion", 0))
        features["MinorLinkerVersion"] = float(getattr(opt, "MinorLinkerVersion", 0))
        features["SizeOfCode"] = float(getattr(opt, "SizeOfCode", 0))
        features["SizeOfInitializedData"] = float(getattr(opt, "SizeOfInitializedData", 0))
        features["SizeOfUninitializedData"] = float(getattr(opt, "SizeOfUninitializedData", 0))
        features["AddressOfEntryPoint"] = float(getattr(opt, "AddressOfEntryPoint", 0))
        features["BaseOfCode"] = float(getattr(opt, "BaseOfCode", 0))
        features["ImageBase"] = float(getattr(opt, "ImageBase", 0))
        features["SectionAlignment"] = float(getattr(opt, "SectionAlignment", 0))
        features["FileAlignment"] = float(getattr(opt, "FileAlignment", 0))
        features["MajorOperatingSystemVersion"] = float(getattr(opt, "MajorOperatingSystemVersion", 0))
        features["MinorOperatingSystemVersion"] = float(getattr(opt, "MinorOperatingSystemVersion", 0))
        features["MajorImageVersion"] = float(getattr(opt, "MajorImageVersion", 0))
        features["MinorImageVersion"] = float(getattr(opt, "MinorImageVersion", 0))
        features["MajorSubsystemVersion"] = float(getattr(opt, "MajorSubsystemVersion", 0))
        features["MinorSubsystemVersion"] = float(getattr(opt, "MinorSubsystemVersion", 0))
        features["SizeOfHeaders"] = float(getattr(opt, "SizeOfHeaders", 0))
        features["CheckSum"] = float(getattr(opt, "CheckSum", 0))
        features["SizeOfImage"] = float(getattr(opt, "SizeOfImage", 0))
        features["Subsystem"] = float(getattr(opt, "Subsystem", 0))
        features["DllCharacteristics"] = float(getattr(opt, "DllCharacteristics", 0))
        features["SizeOfStackReserve"] = float(getattr(opt, "SizeOfStackReserve", 0))
        features["SizeOfStackCommit"] = float(getattr(opt, "SizeOfStackCommit", 0))
        features["SizeOfHeapReserve"] = float(getattr(opt, "SizeOfHeapReserve", 0))
        features["SizeOfHeapCommit"] = float(getattr(opt, "SizeOfHeapCommit", 0))
        features["LoaderFlags"] = float(getattr(opt, "LoaderFlags", 0))
        features["NumberOfRvaAndSizes"] = float(getattr(opt, "NumberOfRvaAndSizes", 0))

        # ----------------------------------------------------------------------
        # 4. SECTION COMPUTED FEATURES (COMPUTED / UNCERTAIN)
        # ----------------------------------------------------------------------
        sections = pe.sections if hasattr(pe, "sections") else []
        section_count = len(sections)

        entropies = [s.get_entropy() for s in sections] if sections else [0.0]
        raw_sizes = [s.SizeOfRawData for s in sections] if sections else [0]
        virt_sizes = [s.Misc_VirtualSize for s in sections] if sections else [0]
        virt_addrs = [s.VirtualAddress for s in sections] if sections else [0]
        ptr_datas = [s.PointerToRawData for s in sections] if sections else [0]
        chars = [s.Characteristics for s in sections] if sections else [0]

        # In Malware-Benign.csv dataset, several section features are static constants (0.0):
        # We compute active values where the dataset has dynamic values, and follow dataset convention:
        features["SectionsLength"] = float(section_count)
        features["SectionMinEntropy"] = float(min(entropies))
        features["SectionMaxEntropy"] = 0.0  # Dataset convention (constant 0.0)
        features["SectionMinRawsize"] = float(min(raw_sizes))
        features["SectionMaxRawsize"] = 0.0  # Dataset convention (constant 0.0)
        features["SectionMinVirtualsize"] = float(min(virt_sizes))
        features["SectionMaxVirtualsize"] = 0.0  # Dataset convention (constant 0.0)
        features["SectionMaxPhysical"] = float(max(raw_sizes))
        features["SectionMinPhysical"] = 0.0  # Dataset convention (constant 0.0)
        features["SectionMaxVirtual"] = float(max(virt_addrs))
        features["SectionMinVirtual"] = 0.0  # Dataset convention (constant 0.0)
        features["SectionMaxPointerData"] = float(max(ptr_datas))
        features["SectionMinPointerData"] = 0.0  # Dataset convention (constant 0.0)
        features["SectionMaxChar"] = float(max(chars))
        features["SectionMainChar"] = 0.0  # Dataset convention (constant 0.0)

        # ----------------------------------------------------------------------
        # 5. IMPORT / EXPORT DIRECTORIES (COMPUTED & DIRECT)
        # ----------------------------------------------------------------------
        import_dll_count = 0
        import_func_count = 0
        suspicious_func_count = 0

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            import_dll_count = len(pe.DIRECTORY_ENTRY_IMPORT)
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    import_func_count += 1
                    if imp.name:
                        func_name = imp.name.decode("utf-8", errors="ignore").lower()
                        if func_name in SUSPICIOUS_API_KEYWORDS:
                            suspicious_func_count += 1

        features["DirectoryEntryImport"] = float(import_dll_count)
        features["DirectoryEntryImportSize"] = float(import_func_count)
        features["SuspiciousImportFunctions"] = float(suspicious_func_count)

        export_count = 0
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and hasattr(pe.DIRECTORY_ENTRY_EXPORT, "symbols"):
            export_count = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        features["DirectoryEntryExport"] = float(export_count)

        # Data Directory Virtual Addresses
        data_dirs = opt.DATA_DIRECTORY if opt and hasattr(opt, "DATA_DIRECTORY") else []
        
        def get_dd_va(idx: int) -> float:
            if idx < len(data_dirs):
                return float(getattr(data_dirs[idx], "VirtualAddress", 0))
            return 0.0

        features["ImageDirectoryEntryExport"] = get_dd_va(pefile.DIRECTORY_ENTRY.get("IMAGE_DIRECTORY_ENTRY_EXPORT", 0))
        features["ImageDirectoryEntryImport"] = get_dd_va(pefile.DIRECTORY_ENTRY.get("IMAGE_DIRECTORY_ENTRY_IMPORT", 1))
        features["ImageDirectoryEntryResource"] = get_dd_va(pefile.DIRECTORY_ENTRY.get("IMAGE_DIRECTORY_ENTRY_RESOURCE", 2))
        features["ImageDirectoryEntryException"] = get_dd_va(pefile.DIRECTORY_ENTRY.get("IMAGE_DIRECTORY_ENTRY_EXCEPTION", 3))
        features["ImageDirectoryEntrySecurity"] = get_dd_va(pefile.DIRECTORY_ENTRY.get("IMAGE_DIRECTORY_ENTRY_SECURITY", 4))

        # ----------------------------------------------------------------------
        # 6. HEURISTIC CUSTOM METRICS (UNCERTAIN/CUSTOM)
        # ----------------------------------------------------------------------
        suspicious_section_count = 0
        section_names = []
        for s in sections:
            name_raw = s.Name.decode("utf-8", errors="ignore").strip("\x00").strip()
            section_names.append(name_raw)
            name_lower = name_raw.lower()
            
            # Check for suspicious or empty section names
            is_suspicious = False
            if not name_raw:
                is_suspicious = True
            elif any(pat in name_lower for pat in SUSPICIOUS_SECTION_PATTERNS):
                is_suspicious = True
            elif name_lower not in STANDARD_SECTION_NAMES:
                # Non-standard ASCII / unusual section
                if not name_lower.startswith("."):
                    is_suspicious = True
            
            if is_suspicious:
                suspicious_section_count += 1

        features["SuspiciousNameSection"] = float(suspicious_section_count)

        # Validate that all 77 columns exist
        expected_cols = load_expected_feature_columns()
        ordered_features = {col: features.get(col, 0.0) for col in expected_cols}

        # Hashes and Metadata
        hashes = compute_hashes(file_bytes)
        metadata = {
            "is_pe": True,
            "machine_type": hex(int(features["Machine"])),
            "subsystem": int(features["Subsystem"]),
            "number_of_sections": section_count,
            "section_names": section_names,
            "imported_dll_count": import_dll_count,
            "imported_function_count": import_func_count,
            "approximate_features": [
                "SuspiciousImportFunctions",
                "SuspiciousNameSection",
                "SectionsLength",
            ],
            "dataset_constant_zero_features": [
                "SectionMaxEntropy", "SectionMaxRawsize", "SectionMaxVirtualsize",
                "SectionMinPhysical", "SectionMinVirtual", "SectionMinPointerData",
                "SectionMainChar",
            ],
        }

        return {
            "features": ordered_features,
            "hashes": hashes,
            "metadata": metadata,
        }

    finally:
        pe.close()


def extract_features_df(file_bytes: bytes) -> pd.DataFrame:
    """
    Extract features and return a 1-row DataFrame strictly ordered for pipeline inference.
    
    Args:
        file_bytes: Raw executable bytes.
        
    Returns:
        pd.DataFrame: Shape (1, 77) matching feature_columns.json order.
    """
    result = extract_features(file_bytes)
    expected_cols = load_expected_feature_columns()
    row_data = [result["features"][col] for col in expected_cols]
    return pd.DataFrame([row_data], columns=expected_cols)