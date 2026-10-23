# 🦎 Chameleon Check

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-26%20passed-brightgreen.svg)](tests/)
[![Dependencies](https://img.shields.io/badge/dependencies-zero%20(stdlib)-success.svg)]()
[![Security](https://img.shields.io/badge/security-phishing%20attachment%20triage-red.svg)]()

> **Spot disguised, spoofed, and high-risk email attachments before they fool anyone.**

Chameleon Check is a lightweight Python security tool that scans filenames or attachment directories and flags files pretending to be something they’re not. It catches dangerous executables, sneaky double extensions (`invoice.pdf.exe`), macro-enabled Office documents, space padding tricks, homoglyphs, and Right-to-Left Override (RTLO) Unicode attacks.

Each file receives an explainable **risk score (0–100)** and a **`LOW`**, **`MEDIUM`**, or **`HIGH`** verdict with all triggered red flags, enabling security analysts and mail triage pipelines to identify malicious attachments in seconds.

---

## 📌 Project Overview

### One-Line Description
> *Chameleon Check is a Python tool that spots disguised and risky email attachments, like `invoice.pdf.exe`, before they fool anyone.*

### Short Summary
Chameleon Check is a lightweight Python security tool that scans a folder or list of filenames and flags attachments pretending to be something they’re not. It catches risky file types (`.exe`, `.js`, `.scr`), double extensions (`invoice.pdf.exe`), macro-enabled Office files, and tricks like hidden spaces or right-to-left override characters. Each file gets a risk score and a `LOW`, `MEDIUM` or `HIGH` verdict with the reasons listed, so analysts can triage suspicious attachments quickly.

---

## 🔍 Why It Exists

Phishing emails routinely disguise malware payloads behind harmless-looking attachment names. Because Windows Explorer historically hides known extensions by default, and email clients often truncate long filenames or render Unicode bidirectionally, attackers use masquerading techniques to trick users:

* **Double Extensions:** A file called `invoice.pdf.exe` displays with a PDF icon or looks like a document, but executes as a binary program.
* **Space Padding:** An attacker adds 20 spaces (`statement.pdf                  .exe`) to shove the `.exe` extension out of the preview column.
* **Right-to-Left Override (RTLO Trojan):** Inserting the Unicode character `\u202E` reverses character rendering, transforming `report_fdp.exe` visually into `report_exe.pdf`.
* **Homoglyph Spoofing:** Replacing Latin characters with visually identical Cyrillic letters (e.g. `setup.ехе`) to evade naive string matchers.
* **Macro Payloads & Container Loaders:** Macro documents (`.xlsm`, `.docm`) or disk images (`.iso`, `.img`) designed to bypass Mark-of-the-Web (MOTW) sandbox controls.

Like a chameleon, these files alter their appearance to blend in with trusted business documents. **Chameleon Check strips away the camouflage.**

---

## ✨ Key Features & Detection Capabilities

| Detection Category | Attack Technique / Vector | Example | Severity Impact |
| :--- | :--- | :--- | :--- |
| **Double Extension** | Decoy extension followed by executable or script | `invoice.pdf.exe`, `bonus.xlsx.vbs` | **HIGH** (+60 pts) |
| **RTLO BiDi Trojan** | Unicode `\u202E` reverses how the name renders | `doc_\u202Efdp.exe` (renders `docexe.pdf`) | **HIGH** (+70 pts) |
| **Space Padding** | Consecutive whitespace hiding dangerous extension | `statement.pdf             .exe` | **HIGH** (+45 pts) |
| **Homoglyph Spoofing** | Cyrillic or Greek lookalikes replacing Latin characters | `setup.ехе` (Cyrillic `е`, `х`) | **HIGH** (+40 pts) |
| **Trailing Char Evasion** | Trailing dots or spaces stripped by Windows on run | `malware.exe.` or `payload.exe ` | **MEDIUM / HIGH** (+35 pts) |
| **Zero-Width Invisible** | Zero-width spaces (`\u200B`, `\uFEFF`) to break regex | `invo​ice.pdf.exe` | **MEDIUM** (+40 pts) |
| **Macro-Enabled Office** | Weaponizable VBA macro document types | `quarterly_numbers.xlsm` | **MEDIUM** (+35 pts) |
| **MOTW Evasion Containers** | Disk images abused to bypass Mark-of-the-Web | `invoice_docs.iso`, `scan.img` | **MEDIUM** (+35 pts) |
| **Dangerous Standalone** | Raw executables, scripts, or shortcuts | `.scr`, `.hta`, `.ps1`, `.bat`, `.lnk` | **MEDIUM / HIGH** (+35–45 pts) |
| **Compound Whitelist** | Prevents false positives on valid compound extensions | `archive.tar.gz`, `bundle.min.js` | **LOW** (0 pts) |

---

## 🎯 Scoring & Verdict Matrix

Chameleon Check uses an additive, transparent point system capped at 100:

| Total Score | Verdict | Classification | Recommended Action |
| :---: | :---: | :--- | :--- |
| **60 – 100** | `HIGH` | **Critical / Malicious Masquerading** | Quarantine attachment immediately; block email; inspect binary. |
| **25 – 59** | `MEDIUM` | **Suspicious / Potentially Unsafe** | Review macro policies; warn recipient; sandboxed execution recommended. |
| **0 – 24** | `LOW` | **Standard / Benign Attachment** | Standard processing; normal delivery. |

---

## 🚀 Quickstart & Installation

Chameleon Check requires **Python 3.8+** and uses **only standard library modules**. No external dependencies are needed for core scanning, reporting, JSON, or CSV output!

```bash
# Clone the repository
git clone https://github.com/leelakrishnakurra97/Chameleon-Check.git
cd Chameleon-Check

# Verify scanner works immediately
python chameleon_check.py --names "invoice.pdf.exe" "report.pdf"
```

---

## 💻 CLI Usage Guide

### 1. Scan a Single Filename or File Path
```bash
python chameleon_check.py --file invoice.pdf.exe
```

### 2. Scan a Directory of Attachments
```bash
# Scan a folder of email attachments
python chameleon_check.py --dir sample_attachments

# Scan recursively through subfolders
python chameleon_check.py --dir ./downloads --recursive
```

### 3. Scan a Direct List of Filenames
```bash
python chameleon_check.py --names "invoice.pdf.exe" "bonus.xlsx.vbs" "contract.pdf"
```

### 4. Read Filenames from a Text File
```bash
python chameleon_check.py --file-list attachment_list.txt
```

### 5. Pipe from Stdin (Unix Pipe / PowerShell)
```bash
# PowerShell
Get-Content attachments.txt | python chameleon_check.py -

# Bash / Zsh
cat attachments.txt | python chameleon_check.py -
```

### 6. Verbose Mode (Detailed Rule Explanations)
```bash
python chameleon_check.py --file "invoice.pdf.exe" --verbose
```

### 7. Export to JSON or CSV
```bash
# Terminal JSON
python chameleon_check.py --dir sample_attachments --json

# Save report directly to file
python chameleon_check.py --dir sample_attachments -o report.json
python chameleon_check.py --dir sample_attachments -o report.csv
```

### 8. Pipeline & CI/CD Security Gate
Use `--fail-on-high` in automated pipelines, git hooks, or email ingestion workers to exit with code `1` if dangerous attachments are detected:
```bash
python chameleon_check.py --dir incoming_mail/ --fail-on-high
```

---

## 🖥️ Example Terminal Output

```text
=== Chameleon Check v1.0.0 -- Email Attachment Deception Scanner ===

FILENAME                              REAL EXT    DECOY       SCORE    VERDICT     PRIMARY RED FLAGS
----------------------------------------------------------------------------------------------------
employee_handbook.docx.hta            .hta        .docx       60/100   [HIGH]      Double Extension (Decoy + Executable)
invoice.pdf.exe                       .exe        .pdf        60/100   [HIGH]      Double Extension (Decoy + Executable)
vacation_photo.jpg.scr                .scr        .jpg        60/100   [HIGH]      Double Extension (Decoy + Executable)
quarterly_financials.xlsx.vbs         .vbs        .xlsx       55/100   [MEDIUM]    Double Extension (Decoy + Script)
firmware_update.iso                   .iso        -           35/100   [MEDIUM]    Disk Image / Container Format
macro_payroll.xlsm                    .xlsm       -           35/100   [MEDIUM]    Macro-Enabled Office Document
company_logo.png                      .png        -           0/100    [LOW]       None detected (Benign)
legitimate_report.pdf                 .pdf        -           0/100    [LOW]       None detected (Benign)
project_notes.txt                     .txt        -           0/100    [LOW]       None detected (Benign)
release_archive.tar.gz                .gz         -           0/100    [LOW]       None detected (Benign)

----------------------------------------------------------------------------------------------------
Scan Summary: Total Scanned: 10 | HIGH: 3 | MEDIUM: 3 | LOW: 4
```

In `--verbose` mode, you see exact point penalties, detected character codes, and rendered UI simulations:

```text
financial_report.pdf               .exe   .exe   .pdf   100/100  [HIGH]  Space Padding Before Real Extension
      [+45 pts] Space Padding Before Real Extension: Multiple whitespace characters inserted between extensions.
                 Details: Matched padding pattern: '.pdf               .exe'
      [+60 pts] Double Extension (Decoy + Executable): File masquerades as a harmless '.pdf' document but is executable.
                 Details: Decoy extension: .pdf | True extension: .exe
```

---

## 🐍 Python Library / Programmatic Usage

You can import Chameleon Check directly into your Python security tools, mail filtering scripts, or SIEM pipelines:

```python
from chameleon_check import scan_filename, scan_directory, ChameleonScanner

# 1. Quick check on a single filename
result = scan_filename("quarterly_update.pdf.exe")
print(f"Verdict: {result.verdict.value} (Score: {result.score}/100)")
for hit in result.rule_hits:
    print(f" - [{hit.rule_id}] {hit.name} (+{hit.points} pts)")

# 2. Inspect a directory
results = scan_directory("./incoming_attachments")
for r in results:
    if r.verdict.value == "HIGH":
        print(f"Quarantine: {r.filename} -> True extension: {r.real_extension}")

# 3. Custom scanner with organizational extension rules
custom_scanner = ChameleonScanner(
    custom_executables=[".custombinary"],
    custom_scripts=[".myhook"]
)
custom_result = custom_scanner.scan_filename("document.pdf.custombinary")
print(custom_result.verdict)
```

---

## 🧪 Running Tests

The test suite covers double extensions, RTLO Unicode simulation, space padding, Cyrillic homoglyphs, zero-width characters, compound extensions, and CLI exit codes.

```bash
# Run with pytest
python -m pytest tests/ -v
```

Output:
```text
tests/test_chameleon_check.py::TestFilenameSplitting::test_single_extension PASSED
tests/test_chameleon_check.py::TestDoubleExtensionDetection::test_pdf_exe_double_extension PASSED
tests/test_chameleon_check.py::TestRTLOAttacks::test_right_to_left_override_detection PASSED
tests/test_chameleon_check.py::TestHomoglyphAndInvisibleChars::test_cyrillic_homoglyphs PASSED
...
============================= 26 passed in 0.96s =============================
```

---

## 📁 Project Structure

```text
Chameleon-Check/
├── chameleon_check.py          # Core scanner, rule engine, and CLI entrypoint
├── README.md                   # Complete documentation and usage guide
├── LICENSE                     # MIT License
├── .gitignore                  # Python ignore rules
├── sample_attachments/         # Test fixtures and demonstration files
│   ├── invoice.pdf.exe
│   ├── quarterly_financials.xlsx.vbs
│   ├── employee_handbook.docx.hta
│   ├── vacation_photo.jpg.scr
│   ├── macro_payroll.xlsm
│   ├── firmware_update.iso
│   ├── legitimate_report.pdf
│   ├── company_logo.png
│   ├── project_notes.txt
│   └── release_archive.tar.gz
└── tests/
    └── test_chameleon_check.py # 26 automated unit and integration tests
```

---

## 🛡️ Skills Demonstrated

* **Python Engineering:** Clean, type-annotated, object-oriented, zero-dependency standard library design.
* **String & Path Manipulation:** Advanced parsing, path handling, whitespace normalization, and multi-dot compound analysis.
* **Unicode & Character Security:** Right-to-Left Override (RLO / BiDi) analysis, zero-width characters, and Cyrillic/Greek homoglyph detection.
* **Rule-Based Threat Detection:** Weighted scoring heuristics, transparent verdict calculation, and false-positive suppression.
* **Social Engineering Indicators:** Deep understanding of phishing tactics, execution evasion, and email attachment disguise mechanisms.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
