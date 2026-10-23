"""
Unit and integration tests for Chameleon Check.
Verifies attachment deception and risk detection rules.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import pytest

from chameleon_check import (
    ChameleonScanner,
    ScanVerdict,
    scan_filename,
    scan_directory,
    scan_list,
    sanitize_unprintable,
    simulate_bidi_rendering,
    normalize_homoglyphs,
    split_filename_parts,
)


class TestFilenameSplitting:
    def test_single_extension(self):
        base, exts = split_filename_parts("report.pdf")
        assert base == "report"
        assert exts == [".pdf"]

    def test_double_extension(self):
        base, exts = split_filename_parts("invoice.pdf.exe")
        assert base == "invoice"
        assert exts == [".pdf", ".exe"]

    def test_no_extension(self):
        base, exts = split_filename_parts("README")
        assert base == "README"
        assert exts == []

    def test_spaced_extension(self):
        base, exts = split_filename_parts("document.pdf     .exe")
        assert base == "document"
        assert exts == [".pdf", ".exe"]


class TestDoubleExtensionDetection:
    def setup_method(self):
        self.scanner = ChameleonScanner()

    def test_pdf_exe_double_extension(self):
        result = self.scanner.scan_filename("invoice.pdf.exe")
        assert result.verdict == ScanVerdict.HIGH
        assert result.score >= 60
        assert result.real_extension == ".exe"
        assert result.decoy_extension == ".pdf"
        rule_ids = [h.rule_id for h in result.rule_hits]
        assert "RULE-DOUBLE-01" in rule_ids

    def test_xlsx_vbs_double_extension(self):
        result = self.scanner.scan_filename("quarterly_bonus.xlsx.vbs")
        assert result.verdict in (ScanVerdict.MEDIUM, ScanVerdict.HIGH)
        assert result.real_extension == ".vbs"
        assert result.decoy_extension == ".xlsx"
        rule_ids = [h.rule_id for h in result.rule_hits]
        assert "RULE-DOUBLE-02" in rule_ids

    def test_jpg_scr_double_extension(self):
        result = self.scanner.scan_filename("vacation_photo.jpg.scr")
        assert result.verdict == ScanVerdict.HIGH
        assert result.real_extension == ".scr"
        assert result.decoy_extension == ".jpg"
        rule_ids = [h.rule_id for h in result.rule_hits]
        assert "RULE-DOUBLE-01" in rule_ids

    def test_docx_hta_double_extension(self):
        result = self.scanner.scan_filename("employee_handbook.docx.hta")
        assert result.verdict == ScanVerdict.HIGH
        rule_ids = [h.rule_id for h in result.rule_hits]
        assert "RULE-DOUBLE-01" in rule_ids


class TestLegitimateCompoundExtensions:
    def setup_method(self):
        self.scanner = ChameleonScanner()

    def test_tar_gz_not_flagged_as_double_extension(self):
        result = self.scanner.scan_filename("backup.tar.gz")
        assert result.verdict == ScanVerdict.LOW
        assert result.score == 0
        rule_ids = [h.rule_id for h in result.rule_hits]
        assert not any(r.startswith("RULE-DOUBLE") for r in rule_ids)

    def test_tar_bz2(self):
        result = self.scanner.scan_filename("source_code.tar.bz2")
        assert result.verdict == ScanVerdict.LOW
        assert result.score == 0


class TestRTLOAttacks:
    def setup_method(self):
        self.scanner = ChameleonScanner()

    def test_right_to_left_override_detection(self):
        # invoice_fdp\u202Eexe.pdf reversed
        filename = "contract_\u202Efdp.exe"
        result = self.scanner.scan_filename(filename)
        assert result.verdict == ScanVerdict.HIGH
        assert result.score >= 70
        rule_ids = [h.rule_id for h in result.rule_hits]
        assert "RULE-RTLO-01" in rule_ids
        assert "[RIGHT-TO-LEFT:U+202E]" in result.sanitized_name

    def test_bidi_simulation(self):
        simulated = simulate_bidi_rendering("document\u202Efdp.exe")
        assert simulated == "documentexe.pdf"


class TestSpacePaddingAndTrailingChars:
    def setup_method(self):
        self.scanner = ChameleonScanner()

    def test_space_padding_hiding_extension(self):
        filename = "financial_report.pdf               .exe"
        result = self.scanner.scan_filename(filename)
        assert result.verdict == ScanVerdict.HIGH
        rule_ids = [h.rule_id for h in result.rule_hits]
        assert "RULE-PADDING-01" in rule_ids

    def test_trailing_space(self):
        filename = "invoice.pdf.exe "
        result = self.scanner.scan_filename(filename)
        rule_ids = [h.rule_id for h in result.rule_hits]
        assert "RULE-TRAILING-01" in rule_ids

    def test_trailing_dot(self):
        filename = "malware.exe."
        result = self.scanner.scan_filename(filename)
        rule_ids = [h.rule_id for h in result.rule_hits]
        assert "RULE-TRAILING-01" in rule_ids


class TestHomoglyphAndInvisibleChars:
    def setup_method(self):
        self.scanner = ChameleonScanner()

    def test_cyrillic_homoglyphs(self):
        # setup.ехе with Cyrillic 'е' and 'х'
        filename = "setup.\u0435\u0445\u0435"
        result = self.scanner.scan_filename(filename)
        assert result.verdict == ScanVerdict.HIGH
        rule_ids = [h.rule_id for h in result.rule_hits]
        assert "RULE-HOMOGLYPH-01" in rule_ids
        assert "RULE-EXE-01" in rule_ids

    def test_zero_width_space(self):
        filename = "invo\u200Bice.pdf.exe"
        result = self.scanner.scan_filename(filename)
        rule_ids = [h.rule_id for h in result.rule_hits]
        assert "RULE-INVIS-01" in rule_ids


class TestMacroOfficeAndContainers:
    def setup_method(self):
        self.scanner = ChameleonScanner()

    def test_macro_xlsm(self):
        result = self.scanner.scan_filename("macro_payroll.xlsm")
        assert result.verdict == ScanVerdict.MEDIUM
        assert result.score >= 35
        rule_ids = [h.rule_id for h in result.rule_hits]
        assert "RULE-MACRO-01" in rule_ids

    def test_iso_container(self):
        result = self.scanner.scan_filename("invoice_archive.iso")
        assert result.verdict == ScanVerdict.MEDIUM
        assert result.score >= 35
        rule_ids = [h.rule_id for h in result.rule_hits]
        assert "RULE-CONTAINER-01" in rule_ids


class TestBenignFiles:
    def setup_method(self):
        self.scanner = ChameleonScanner()

    def test_safe_pdf(self):
        result = self.scanner.scan_filename("legitimate_contract.pdf")
        assert result.verdict == ScanVerdict.LOW
        assert result.score == 0
        assert len(result.rule_hits) == 0

    def test_safe_png(self):
        result = self.scanner.scan_filename("screenshot.png")
        assert result.verdict == ScanVerdict.LOW
        assert result.score == 0

    def test_safe_txt(self):
        result = self.scanner.scan_filename("notes.txt")
        assert result.verdict == ScanVerdict.LOW
        assert result.score == 0


class TestDirectoryScanning:
    def test_directory_scan(self, tmp_path):
        # Create temp files
        (tmp_path / "safe.pdf").write_text("dummy")
        (tmp_path / "bad.pdf.exe").write_text("dummy")
        (tmp_path / "macro.xlsm").write_text("dummy")

        results = scan_directory(tmp_path)
        assert len(results) == 3
        # Should be ranked highest score first
        assert results[0].filename == "bad.pdf.exe"
        assert results[0].verdict == ScanVerdict.HIGH
        assert results[-1].filename == "safe.pdf"
        assert results[-1].verdict == ScanVerdict.LOW


class TestCLIExecution:
    def test_cli_names_json(self):
        cmd = [
            sys.executable,
            "chameleon_check.py",
            "--names",
            "invoice.pdf.exe",
            "safe_report.pdf",
            "--json"
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        data = json.loads(proc.stdout)
        assert data["tool"] == "Chameleon Check"
        assert data["total_scanned"] == 2
        assert data["verdict_counts"]["HIGH"] == 1
        assert data["verdict_counts"]["LOW"] == 1

    def test_cli_fail_on_high(self):
        cmd = [
            sys.executable,
            "chameleon_check.py",
            "--names",
            "invoice.pdf.exe",
            "--fail-on-high"
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        assert proc.returncode == 1

    def test_cli_fail_on_high_clean(self):
        cmd = [
            sys.executable,
            "chameleon_check.py",
            "--names",
            "safe_report.pdf",
            "--fail-on-high"
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        assert proc.returncode == 0
