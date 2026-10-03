# PE Feature Extraction Mapping Reference

This document provides a comprehensive technical mapping between each of the **77 raw input features** expected by the trained Malware Classification pipeline and the corresponding Portable Executable (PE) metadata structures extracted via the [`pefile`](https://github.com/erocarrera/pefile) library.

---

## 1. Feature Classification Categories

- **DIRECT (`55` features):** Standard, unambiguous header attributes directly readable from `DOS_HEADER`, `FILE_HEADER`, `OPTIONAL_HEADER`, or `DATA_DIRECTORY` entries in `pefile`.
- **COMPUTED (`19` features):** Derivable from PE section tables and import/export tables using standard deterministic aggregation formulas (e.g. min/max section entropy, min/max raw sizes, imported DLL count, imported function count).
- **UNCERTAIN / CUSTOM (`3` features):** Heuristic or custom dataset-specific metrics (`SuspiciousImportFunctions`, `SuspiciousNameSection`, `SectionsLength`). For these, a reconstructed approximation is documented and implemented.

---

## 2. Complete 77-Feature Extraction Table

| # | Feature Name | Classification | Source / Attribute Path in `pefile` | Extraction Formula / Logic | Confidence |
|---|---|---|---|---|---|
| 1 | `e_magic` | DIRECT | `pe.DOS_HEADER.e_magic` | Value of MS-DOS Magic Number (`0x5A4D` = `23117`) | High |
| 2 | `e_cblp` | DIRECT | `pe.DOS_HEADER.e_cblp` | Bytes on last page of file | High |
| 3 | `e_cp` | DIRECT | `pe.DOS_HEADER.e_cp` | Pages in file | High |
| 4 | `e_crlc` | DIRECT | `pe.DOS_HEADER.e_crlc` | Relocations | High |
| 5 | `e_cparhdr` | DIRECT | `pe.DOS_HEADER.e_cparhdr` | Size of header in paragraphs | High |
| 6 | `e_minalloc` | DIRECT | `pe.DOS_HEADER.e_minalloc` | Minimum extra paragraphs needed | High |
| 7 | `e_maxalloc` | DIRECT | `pe.DOS_HEADER.e_maxalloc` | Maximum extra paragraphs needed | High |
| 8 | `e_ss` | DIRECT | `pe.DOS_HEADER.e_ss` | Initial (relative) SS value | High |
| 9 | `e_sp` | DIRECT | `pe.DOS_HEADER.e_sp` | Initial SP value | High |
| 10 | `e_csum` | DIRECT | `pe.DOS_HEADER.e_csum` | Checksum | High |
| 11 | `e_ip` | DIRECT | `pe.DOS_HEADER.e_ip` | Initial IP value | High |
| 12 | `e_cs` | DIRECT | `pe.DOS_HEADER.e_cs` | Initial (relative) CS value | High |
| 13 | `e_lfarlc` | DIRECT | `pe.DOS_HEADER.e_lfarlc` | File address of relocation table | High |
| 14 | `e_ovno` | DIRECT | `pe.DOS_HEADER.e_ovno` | Overlay number | High |
| 15 | `e_oemid` | DIRECT | `pe.DOS_HEADER.e_oemid` | OEM identifier | High |
| 16 | `e_oeminfo` | DIRECT | `pe.DOS_HEADER.e_oeminfo` | OEM information | High |
| 17 | `e_lfanew` | DIRECT | `pe.DOS_HEADER.e_lfanew` | File address of new exe header (NT Header offset) | High |
| 18 | `Machine` | DIRECT | `pe.FILE_HEADER.Machine` | Target CPU architecture (e.g., `0x014C` = i386, `0x8664` = AMD64) | High |
| 19 | `NumberOfSections` | DIRECT | `pe.FILE_HEADER.NumberOfSections` | Number of section headers | High |
| 20 | `TimeDateStamp` | DIRECT | `pe.FILE_HEADER.TimeDateStamp` | Epoch timestamp of compilation | High |
| 21 | `PointerToSymbolTable` | DIRECT | `pe.FILE_HEADER.PointerToSymbolTable` | File offset of COFF symbol table | High |
| 22 | `NumberOfSymbols` | DIRECT | `pe.FILE_HEADER.NumberOfSymbols` | Number of entries in symbol table | High |
| 23 | `SizeOfOptionalHeader` | DIRECT | `pe.FILE_HEADER.SizeOfOptionalHeader` | Size of the Optional Header in bytes | High |
| 24 | `Characteristics` | DIRECT | `pe.FILE_HEADER.Characteristics` | Flags indicating binary attributes | High |
| 25 | `Magic` | DIRECT | `pe.OPTIONAL_HEADER.Magic` | Optional header state (`0x010B` = PE32, `0x020B` = PE32+) | High |
| 26 | `MajorLinkerVersion` | DIRECT | `pe.OPTIONAL_HEADER.MajorLinkerVersion` | Linker major version | High |
| 27 | `MinorLinkerVersion` | DIRECT | `pe.OPTIONAL_HEADER.MinorLinkerVersion` | Linker minor version | High |
| 28 | `SizeOfCode` | DIRECT | `pe.OPTIONAL_HEADER.SizeOfCode` | Size of code section (`.text`) in bytes | High |
| 29 | `SizeOfInitializedData` | DIRECT | `pe.OPTIONAL_HEADER.SizeOfInitializedData` | Size of initialized data sections in bytes | High |
| 30 | `SizeOfUninitializedData` | DIRECT | `pe.OPTIONAL_HEADER.SizeOfUninitializedData` | Size of uninitialized data section (`.bss`) | High |
| 31 | `AddressOfEntryPoint` | DIRECT | `pe.OPTIONAL_HEADER.AddressOfEntryPoint` | Relative virtual address (RVA) of entry point | High |
| 32 | `BaseOfCode` | DIRECT | `pe.OPTIONAL_HEADER.BaseOfCode` | RVA of beginning of code section | High |
| 33 | `ImageBase` | DIRECT | `pe.OPTIONAL_HEADER.ImageBase` | Preferred memory base address | High |
| 34 | `SectionAlignment` | DIRECT | `pe.OPTIONAL_HEADER.SectionAlignment` | Alignment of sections loaded into memory | High |
| 35 | `FileAlignment` | DIRECT | `pe.OPTIONAL_HEADER.FileAlignment` | Alignment of sections stored on disk | High |
| 36 | `MajorOperatingSystemVersion` | DIRECT | `pe.OPTIONAL_HEADER.MajorOperatingSystemVersion` | Major OS version required | High |
| 37 | `MinorOperatingSystemVersion` | DIRECT | `pe.OPTIONAL_HEADER.MinorOperatingSystemVersion` | Minor OS version required | High |
| 38 | `MajorImageVersion` | DIRECT | `pe.OPTIONAL_HEADER.MajorImageVersion` | Major image version | High |
| 39 | `MinorImageVersion` | DIRECT | `pe.OPTIONAL_HEADER.MinorImageVersion` | Minor image version | High |
| 40 | `MajorSubsystemVersion` | DIRECT | `pe.OPTIONAL_HEADER.MajorSubsystemVersion` | Major subsystem version | High |
| 41 | `MinorSubsystemVersion` | DIRECT | `pe.OPTIONAL_HEADER.MinorSubsystemVersion` | Minor subsystem version | High |
| 42 | `SizeOfHeaders` | DIRECT | `pe.OPTIONAL_HEADER.SizeOfHeaders` | Combined size of MS-DOS, PE headers, and section headers | High |
| 43 | `CheckSum` | DIRECT | `pe.OPTIONAL_HEADER.CheckSum` | Image checksum validation value | High |
| 44 | `SizeOfImage` | DIRECT | `pe.OPTIONAL_HEADER.SizeOfImage` | Total size of image loaded in memory | High |
| 45 | `Subsystem` | DIRECT | `pe.OPTIONAL_HEADER.Subsystem` | Target subsystem (GUI, Console, Driver) | High |
| 46 | `DllCharacteristics` | DIRECT | `pe.OPTIONAL_HEADER.DllCharacteristics` | Security mitigation flags (ASLR, DEP, CFG) | High |
| 47 | `SizeOfStackReserve` | DIRECT | `pe.OPTIONAL_HEADER.SizeOfStackReserve` | Reserved stack size in bytes | High |
| 48 | `SizeOfStackCommit` | DIRECT | `pe.OPTIONAL_HEADER.SizeOfStackCommit` | Committed stack size in bytes | High |
| 49 | `SizeOfHeapReserve` | DIRECT | `pe.OPTIONAL_HEADER.SizeOfHeapReserve` | Reserved local heap space | High |
| 50 | `SizeOfHeapCommit` | DIRECT | `pe.OPTIONAL_HEADER.SizeOfHeapCommit` | Committed local heap space | High |
| 51 | `LoaderFlags` | DIRECT | `pe.OPTIONAL_HEADER.LoaderFlags` | Reserved loader control flags | High |
| 52 | `NumberOfRvaAndSizes` | DIRECT | `pe.OPTIONAL_HEADER.NumberOfRvaAndSizes` | Number of Data Directory array entries (typically 16) | High |
| 53 | `SuspiciousImportFunctions` | UNCERTAIN/CUSTOM | `pe.DIRECTORY_ENTRY_IMPORT` | Count of imported API functions matching known malicious/hooking/injection signatures (e.g. `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`, `SetWindowsHookEx`, `IsDebuggerPresent`, `URLDownloadToFile`, `WinExec`) | Medium *(Reconstructed approximation)* |
| 54 | `SuspiciousNameSection` | UNCERTAIN/CUSTOM | `pe.sections` | Count of section names matching packer/crypter artifacts or non-standard signatures (e.g. `UPX0`, `UPX1`, `.aspack`, `.mpress`, empty names, non-ASCII) | Medium *(Reconstructed approximation)* |
| 55 | `SectionsLength` | UNCERTAIN/CUSTOM | `pe.sections` / `pe.FILE_HEADER.NumberOfSections` | Section list count (`len(pe.sections)` or `NumberOfSections`) | High |
| 56 | `SectionMinEntropy` | COMPUTED | `pe.sections[i].get_entropy()` | $\min(\{\text{s.get\_entropy()} \mid \text{s} \in \text{pe.sections}\})$ or `0.0` | High |
| 57 | `SectionMaxEntropy` | COMPUTED | Dataset Convention / Section Entropy | Constant `0.0` in dataset (mapped to `0.0` for consistency with trained model) | High |
| 58 | `SectionMinRawsize` | COMPUTED | `pe.sections[i].SizeOfRawData` | $\min(\{\text{s.SizeOfRawData} \mid \text{s} \in \text{pe.sections}\})$ or `0.0` | High |
| 59 | `SectionMaxRawsize` | COMPUTED | Dataset Convention / Raw Size | Constant `0.0` in dataset (mapped to `0.0`) | High |
| 60 | `SectionMinVirtualsize` | COMPUTED | `pe.sections[i].Misc_VirtualSize` | $\min(\{\text{s.Misc\_VirtualSize} \mid \text{s} \in \text{pe.sections}\})$ or `0.0` | High |
| 61 | `SectionMaxVirtualsize` | COMPUTED | Dataset Convention / Virtual Size | Constant `0.0` in dataset (mapped to `0.0`) | High |
| 62 | `SectionMaxPhysical` | COMPUTED | `pe.sections[i].SizeOfRawData` | $\max(\{\text{s.SizeOfRawData} \mid \text{s} \in \text{pe.sections}\})$ or `0.0` | High |
| 63 | `SectionMinPhysical` | COMPUTED | Dataset Convention | Constant `0.0` in dataset (mapped to `0.0`) | High |
| 64 | `SectionMaxVirtual` | COMPUTED | `pe.sections[i].VirtualAddress` | $\max(\{\text{s.VirtualAddress} \mid \text{s} \in \text{pe.sections}\})$ or `0.0` | High |
| 65 | `SectionMinVirtual` | COMPUTED | Dataset Convention | Constant `0.0` in dataset (mapped to `0.0`) | High |
| 66 | `SectionMaxPointerData` | COMPUTED | `pe.sections[i].PointerToRawData` | $\max(\{\text{s.PointerToRawData} \mid \text{s} \in \text{pe.sections}\})$ or `0.0` | High |
| 67 | `SectionMinPointerData` | COMPUTED | Dataset Convention | Constant `0.0` in dataset (mapped to `0.0`) | High |
| 68 | `SectionMaxChar` | COMPUTED | `pe.sections[i].Characteristics` | $\max(\{\text{s.Characteristics} \mid \text{s} \in \text{pe.sections}\})$ or `0.0` | High |
| 69 | `SectionMainChar` | COMPUTED | Dataset Convention | Constant `0.0` in dataset (mapped to `0.0`) | High |
| 70 | `DirectoryEntryImport` | COMPUTED | `pe.DIRECTORY_ENTRY_IMPORT` | Number of imported DLL modules (`len(pe.DIRECTORY_ENTRY_IMPORT)` if present, else 0) | High |
| 71 | `DirectoryEntryImportSize` | COMPUTED | `pe.DIRECTORY_ENTRY_IMPORT` | Total number of imported functions (`sum(len(e.imports) for e in pe.DIRECTORY_ENTRY_IMPORT)` if present, else 0) | High |
| 72 | `DirectoryEntryExport` | COMPUTED | `pe.DIRECTORY_ENTRY_EXPORT` | Total number of exported functions (`len(pe.DIRECTORY_ENTRY_EXPORT.symbols)` if present, else 0) | High |
| 73 | `ImageDirectoryEntryExport` | DIRECT | `pe.OPTIONAL_HEADER.DATA_DIRECTORY[0]` | Virtual Address of Export Table | High |
| 74 | `ImageDirectoryEntryImport` | DIRECT | `pe.OPTIONAL_HEADER.DATA_DIRECTORY[1]` | Virtual Address of Import Table | High |
| 75 | `ImageDirectoryEntryResource` | DIRECT | `pe.OPTIONAL_HEADER.DATA_DIRECTORY[2]` | Virtual Address of Resource Table | High |
| 76 | `ImageDirectoryEntryException` | DIRECT | `pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]` | Virtual Address of Exception Table | High |
| 77 | `ImageDirectoryEntrySecurity` | DIRECT | `pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]` | Virtual Address of Security / Certificate Table | High |

---

## 3. Detailed Specification for Uncertain / Custom Features

> [!NOTE]
> *The following features are reconstructed approximations based on domain knowledge and empirical dataset analysis, not verified against the original dataset build script.*

### A. `SuspiciousImportFunctions`
- **Definition:** Count of imported Win32 API functions known to be heavily leveraged in malware execution chains (e.g. process injection, memory allocation, privilege escalation, keyboard hooks, and anti-debugging).
- **Matching Keyword Set:**
  - *Process Injection & Memory:* `VirtualAlloc`, `VirtualAllocEx`, `VirtualProtect`, `VirtualProtectEx`, `WriteProcessMemory`, `ReadProcessMemory`, `CreateRemoteThread`, `NtCreateThreadEx`, `QueueUserAPC`, `SetThreadContext`
  - *Execution & Spawning:* `CreateProcessA`, `CreateProcessW`, `WinExec`, `ShellExecuteA`, `ShellExecuteW`, `ShellExecuteExA`, `ShellExecuteExW`, `OpenProcess`
  - *Dynamic Loading & Hooking:* `LoadLibraryA`, `LoadLibraryW`, `LoadLibraryExA`, `LoadLibraryExW`, `GetProcAddress`, `SetWindowsHookExA`, `SetWindowsHookExW`, `UnhookWindowsHookEx`
  - *Anti-Analysis:* `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `OutputDebugStringA`, `OutputDebugStringW`, `NtQueryInformationProcess`, `FindWindowA`, `FindWindowW`
  - *Persistence & Registry:* `RegOpenKeyExA`, `RegOpenKeyExW`, `RegSetValueExA`, `RegSetValueExW`, `RegCreateKeyExA`, `RegCreateKeyExW`
  - *Network & Dropping:* `URLDownloadToFileA`, `URLDownloadToFileW`, `InternetOpenA`, `InternetOpenW`, `InternetConnectA`, `InternetConnectW`, `HttpOpenRequestA`, `HttpOpenRequestW`, `HttpSendRequestA`, `HttpSendRequestW`, `WSAStartup`, `connect`, `send`, `recv`
  - *Keylogging & Input:* `GetAsyncKeyState`, `GetKeyState`, `GetKeyboardState`, `RegisterHotKey`

### B. `SuspiciousNameSection`
- **Definition:** Count of section names within the PE header that deviate from standard Windows compiler conventions or match known packing/crypter signatures.
- **Standard Names (Non-suspicious):** `{".text", ".data", ".rdata", ".idata", ".edata", ".rsrc", ".reloc", ".bss", ".tls", ".pdata", ".debug", ".gfids", ".giats", ".didat"}`
- **Suspicious Signatures:** Section names containing `UPX`, `aspack`, `mpress`, `themida`, `vmp`, `enigma`, `packed`, empty strings `""`, or names with non-printable ASCII characters.

### C. `SectionsLength`
- **Definition:** Number of sections declared in the PE section table (`len(pe.sections)`), which matches `NumberOfSections` in standard PE files.