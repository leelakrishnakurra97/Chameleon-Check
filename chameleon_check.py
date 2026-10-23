#!/usr/bin/env python3
"""
Chameleon Check - Attachment Deception & Masquerading Detection Tool
Spot disguised, spoofed, and high-risk email attachments before they fool anyone.

Author: Leela Krishna Kurra
Repository: https://github.com/leelakrishnakurra97/Chameleon-Check
License: MIT
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import asdict, dataclass, field
from enum import Enum
import io
import json
import os
from pathlib import Path
import re
import sys
import unicodedata
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

__version__ = "1.0.0"
__tool_name__ = "Chameleon Check"

if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# -----------------------------------------------------------------------------
# Extension Classifications & Knowledge Base
# -----------------------------------------------------------------------------

DANGEROUS_EXECUTABLES: Set[str] = {
    ".exe", ".scr", ".pif", ".com", ".cpl", ".msi", ".msp", ".gadget",
    ".app", ".hta", ".msc", ".jar", ".application", ".appx", ".appxbundle"
}

DANGEROUS_SCRIPTS: Set[str] = {
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".ps1xml",
    ".ps2", ".psc1", ".psc2", ".bat", ".cmd", ".sh", ".bash", ".py",
    ".pyw", ".reg", ".inf", ".scf", ".sct", ".vsd", ".vsdx"
}

MACRO_OFFICE_EXTENSIONS: Set[str] = {
    ".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm",
    ".ppam", ".ppsm", ".sldm", ".xlsb"
}

SUSPICIOUS_CONTAINERS: Set[str] = {
    ".iso", ".img", ".vhd", ".vhdx", ".dmg", ".cab", ".ar"
}

SHORTCUT_EXTENSIONS: Set[str] = {
    ".lnk", ".url", ".iqy", ".desklink", ".mapimail", ".settingcontent-ms"
}

COMMON_DECOY_EXTENSIONS: Set[str] = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt",
    ".rtf", ".csv", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
    ".svg", ".tif", ".tiff", ".mp3", ".mp4", ".wav", ".avi", ".mov",
    ".zip", ".rar", ".7z"
}

# Known benign compound extensions that are legitimate multi-part extensions
LEGITIMATE_COMPOUND_EXTENSIONS: Set[str] = {
    ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tar.lz", ".tar.lzma",
    ".user.js", ".min.js", ".min.css", ".d.ts", ".spec.ts", ".test.ts",
    ".spec.js", ".test.js", ".blade.php", ".config.js", ".theme.css"
}

# Unicode directional override characters commonly used in RTLO spoofing attacks
UNICODE_BIDI_OVERRIDES: Dict[str, str] = {
    "\u202E": "RIGHT-TO-LEFT OVERRIDE (RLO)",
    "\u202D": "LEFT-TO-RIGHT OVERRIDE (LRO)",
    "\u202A": "LEFT-TO-RIGHT EMBEDDING (LRE)",
    "\u202B": "RIGHT-TO-LEFT EMBEDDING (RLE)",
    "\u202C": "POP DIRECTIONAL FORMATTING (PDF)",
    "\u2066": "LEFT-TO-RIGHT ISOLATE (LRI)",
    "\u2067": "RIGHT-TO-LEFT ISOLATE (RLI)",
    "\u2068": "FIRST STRONG ISOLATE (FSI)",
    "\u2069": "POP DIRECTIONAL ISOLATE (PDI)",
    "\u200E": "LEFT-TO-RIGHT MARK (LRM)",
    "\u200F": "RIGHT-TO-LEFT MARK (RLM)",
}

# Zero-width, invisible, and format characters
ZERO_WIDTH_AND_INVISIBLE_CHARS: Dict[str, str] = {
    "\u200B": "ZERO WIDTH SPACE",
    "\u200C": "ZERO WIDTH NON-JOINER",
    "\u200D": "ZERO WIDTH JOINER",
    "\uFEFF": "ZERO WIDTH NO-BREAK SPACE / BOM",
    "\u2060": "WORD JOINER",
    "\u00A0": "NO-BREAK SPACE",
    "\u2000": "EN QUAD",
    "\u2001": "EM QUAD",
    "\u2002": "EN SPACE",
    "\u2003": "EM SPACE",
    "\u2004": "THREE-PER-EM SPACE",
    "\u2005": "FOUR-PER-EM SPACE",
    "\u2006": "SIX-PER-EM SPACE",
    "\u2007": "FIGURE SPACE",
    "\u2008": "PUNCTUATION SPACE",
    "\u2009": "THIN SPACE",
    "\u200A": "HAIR SPACE",
    "\u202F": "NARROW NO-BREAK SPACE",
    "\u205F": "MEDIUM MATHEMATICAL SPACE",
    "\u3000": "IDEOGRAPHIC SPACE",
}

# Cyrillic / Greek lookalikes for standard ASCII Latin alphabet
CYRILLIC_GREEK_HOMOGLYPHS: Dict[str, str] = {
    # Cyrillic small letters
    "\u0430": "a", "\u0441": "c", "\u0435": "e", "\u0456": "i", "\u0458": "j",
    "\u043E": "o", "\u0440": "p", "\u0455": "s", "\u0445": "x", "\u0443": "y",
    "\u0432": "v", "\u043A": "k", "\u043C": "m", "\u0442": "t",
    # Cyrillic capital letters
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E", "\u041D": "H",
    "\u0406": "I", "\u0408": "J", "\u041A": "K", "\u041C": "M", "\u041E": "O",
    "\u0420": "P", "\u0422": "T", "\u0425": "X", "\u0423": "Y",
    # Greek small and capital letters
    "\u03BF": "o", "\u03BD": "v", "\u03C1": "p", "\u03B1": "a", "\u03B5": "e",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H", "\u0399": "I",
    "\u039A": "K", "\u039C": "M", "\u039D": "N", "\u039F": "O", "\u03A1": "P",
    "\u03A4": "T", "\u03A5": "Y", "\u03A7": "X",
}


# -----------------------------------------------------------------------------
# Data Models
# -----------------------------------------------------------------------------

class ScanVerdict(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class RuleHit:
    rule_id: str
    name: str
    points: int
    description: str
    details: str = ""


@dataclass
class ScanResult:
    filename: str
    sanitized_name: str
    visual_name: str
    real_extension: str
    decoy_extension: Optional[str]
    score: int
    verdict: ScanVerdict
    rule_hits: List[RuleHit] = field(default_factory=list)
    filepath: Optional[str] = None
    file_size_bytes: Optional[int] = None

    def to_dict(self) -> Dict:
        return {
            "filename": self.filename,
            "sanitized_name": self.sanitized_name,
            "visual_name": self.visual_name,
            "real_extension": self.real_extension,
            "decoy_extension": self.decoy_extension,
            "score": self.score,
            "verdict": self.verdict.value,
            "filepath": self.filepath,
            "file_size_bytes": self.file_size_bytes,
            "rule_hits": [asdict(r) for r in self.rule_hits],
        }


# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

def sanitize_unprintable(text: str) -> str:
    """Replaces invisible / control characters with legible hex representation."""
    out = []
    for char in text:
        code = ord(char)
        if char in UNICODE_BIDI_OVERRIDES:
            out.append(f"[{char in UNICODE_BIDI_OVERRIDES and UNICODE_BIDI_OVERRIDES[char].split()[0]}:U+{code:04X}]")
        elif char in ZERO_WIDTH_AND_INVISIBLE_CHARS:
            out.append(f"[INVIS:U+{code:04X}]")
        elif unicodedata.category(char) in ("Cc", "Cf", "Cs", "Co"):
            out.append(f"[CTRL:U+{code:04X}]")
        else:
            out.append(char)
    return "".join(out)


def simulate_bidi_rendering(text: str) -> str:
    """
    Simulates simple Right-To-Left Override (RLO) visual rendering
    for diagnostic display.
    """
    if "\u202E" not in text:
        return text

    # Split on first RLO character
    before_rlo, _, after_rlo = text.partition("\u202E")
    # In simple GUI renderers, characters after RLO until end-of-string or PDF are inverted
    if "\u202C" in after_rlo:
        rlo_segment, _, remainder = after_rlo.partition("\u202C")
        return before_rlo + rlo_segment[::-1] + remainder
    return before_rlo + after_rlo[::-1]


def normalize_homoglyphs(text: str) -> str:
    """Translates known Cyrillic/Greek homoglyphs to ASCII Latin equivalents."""
    return "".join(CYRILLIC_GREEK_HOMOGLYPHS.get(c, c) for c in text)


def split_filename_parts(filename: str) -> Tuple[str, List[str]]:
    """
    Extracts base filename and list of extensions separated by dots.
    Handles compound extensions and multiple dots.
    """
    # Normalize path separators if path was given
    basename = os.path.basename(filename)
    
    # Check for dots
    if "." not in basename:
        return basename, []
        
    parts = basename.split(".")
    base = parts[0]
    extensions = ["." + p.strip().lower() for p in parts[1:] if p.strip() != ""]
    return base, extensions


# -----------------------------------------------------------------------------
# Core Scanner Engine
# -----------------------------------------------------------------------------

class ChameleonScanner:
    """
    Chameleon Check inspection engine for detecting deceptive attachment names.
    """

    def __init__(
        self,
        custom_executables: Optional[Iterable[str]] = None,
        custom_scripts: Optional[Iterable[str]] = None,
        custom_decoys: Optional[Iterable[str]] = None,
    ):
        self.executables = set(DANGEROUS_EXECUTABLES)
        if custom_executables:
            self.executables.update(ext.lower() if ext.startswith(".") else f".{ext.lower()}" for ext in custom_executables)

        self.scripts = set(DANGEROUS_SCRIPTS)
        if custom_scripts:
            self.scripts.update(ext.lower() if ext.startswith(".") else f".{ext.lower()}" for ext in custom_scripts)

        self.decoys = set(COMMON_DECOY_EXTENSIONS)
        if custom_decoys:
            self.decoys.update(ext.lower() if ext.startswith(".") else f".{ext.lower()}" for ext in custom_decoys)

        self.macro_office = set(MACRO_OFFICE_EXTENSIONS)
        self.containers = set(SUSPICIOUS_CONTAINERS)
        self.shortcuts = set(SHORTCUT_EXTENSIONS)

    def scan_filename(self, filename: str, filepath: Optional[str] = None) -> ScanResult:
        """
        Scans a filename string or path and returns a comprehensive ScanResult.
        """
        basename = os.path.basename(filename)
        hits: List[RuleHit] = []
        score = 0
        decoy_extension: Optional[str] = None

        # 1. Unicode BiDi Override Detection (RTLO / RLO Attacks)
        found_bidi = [c for c in basename if c in UNICODE_BIDI_OVERRIDES]
        if found_bidi:
            bidi_names = [f"U+{ord(c):04X} ({UNICODE_BIDI_OVERRIDES[c]})" for c in found_bidi]
            hits.append(RuleHit(
                rule_id="RULE-RTLO-01",
                name="Right-to-Left Override (BiDi Trojan)",
                points=70,
                description="Filename contains bidirectional override characters designed to visually reverse the apparent file extension in email clients and file explorers.",
                details=f"Detected characters: {', '.join(bidi_names)}"
            ))
            score += 70

        # 2. Zero-Width and Invisible Characters
        found_invisible = [c for c in basename if c in ZERO_WIDTH_AND_INVISIBLE_CHARS]
        if found_invisible:
            invis_details = [f"U+{ord(c):04X} ({ZERO_WIDTH_AND_INVISIBLE_CHARS[c]})" for c in found_invisible]
            hits.append(RuleHit(
                rule_id="RULE-INVIS-01",
                name="Invisible / Zero-Width Characters",
                points=40,
                description="Filename contains zero-width or non-standard whitespace characters often used to defeat signature matchers and evade static filters.",
                details=f"Detected characters: {', '.join(invis_details)}"
            ))
            score += 40

        # 3. Homoglyph / Mixed-Script Character Spoofing
        homoglyphs_found: List[Tuple[str, str]] = []
        for char in basename:
            if char in CYRILLIC_GREEK_HOMOGLYPHS:
                homoglyphs_found.append((char, CYRILLIC_GREEK_HOMOGLYPHS[char]))
        if homoglyphs_found:
            details_list = [f"'{c}' (U+{ord(c):04X}) looks like Latin '{target}'" for c, target in homoglyphs_found]
            hits.append(RuleHit(
                rule_id="RULE-HOMOGLYPH-01",
                name="Homoglyph Spoofing (Mixed-Script)",
                points=40,
                description="Filename uses Cyrillic or Greek lookalike characters masquerading as standard Latin characters.",
                details=f"Detected spoofed characters: {', '.join(details_list)}"
            ))
            score += 40

        # 4. Hidden Spaces & Padding between extensions
        # Attackers put many spaces (e.g. invoice.pdf             .exe) so .exe is pushed out of the UI
        space_padding_match = re.search(r'\.[a-zA-Z0-9]{2,5}(\s{3,}|\t+)\.[a-zA-Z0-9]+', basename)
        if space_padding_match:
            hits.append(RuleHit(
                rule_id="RULE-PADDING-01",
                name="Space Padding Before Real Extension",
                points=45,
                description="Multiple whitespace characters inserted between extensions to push the dangerous extension off-screen in narrow email windows.",
                details=f"Matched padding pattern: '{space_padding_match.group(0)}'"
            ))
            score += 45

        # Trailing spaces or dots
        if basename.endswith(" ") or basename.endswith("."):
            hits.append(RuleHit(
                rule_id="RULE-TRAILING-01",
                name="Trailing Space or Dot Evasion",
                points=35,
                description="Filename ends with trailing whitespace or period. Windows strips trailing dots and spaces during execution, bypassing superficial extension checks.",
                details=f"Raw ending character: {repr(basename[-1])}"
            ))
            score += 35

        # 5. Consecutive Dots (e.g. file..pdf or file...exe)
        if ".." in basename:
            hits.append(RuleHit(
                rule_id="RULE-DOTS-01",
                name="Consecutive Dots Anomaly",
                points=20,
                description="Filename contains multiple consecutive periods, commonly used in extension obfuscation.",
                details="Detected '..' in filename structure"
            ))
            score += 20

        # Clean stripped version for extension parsing
        stripped_basename = basename.strip(" .")
        base_part, extensions = split_filename_parts(stripped_basename)

        # Determine real extension and homoglyph-normalized version
        real_extension = extensions[-1] if extensions else ""
        norm_real_extension = normalize_homoglyphs(real_extension)

        # Check for legitimate compound extensions like .tar.gz
        is_legit_compound = False
        if len(extensions) >= 2:
            compound_candidate = "".join(extensions[-2:]).lower()
            if compound_candidate in LEGITIMATE_COMPOUND_EXTENSIONS:
                is_legit_compound = True

        # 6. Double Extension Detection (Decoy + Dangerous/Executable)
        if len(extensions) >= 2 and not is_legit_compound:
            for ext in extensions[:-1]:
                norm_ext = normalize_homoglyphs(ext)
                if ext in self.decoys or norm_ext in self.decoys:
                    decoy_extension = ext
                    break

            if decoy_extension:
                # Is the real extension dangerous, script, container, or another unexpected extension?
                if real_extension in self.executables or norm_real_extension in self.executables:
                    hits.append(RuleHit(
                        rule_id="RULE-DOUBLE-01",
                        name="Double Extension (Decoy + Executable)",
                        points=60,
                        description=f"File masquerades as a harmless '{decoy_extension}' document but is actually an executable '{real_extension}' program.",
                        details=f"Decoy extension: {decoy_extension} | True extension: {real_extension}"
                    ))
                    score += 60
                elif real_extension in self.scripts or norm_real_extension in self.scripts:
                    hits.append(RuleHit(
                        rule_id="RULE-DOUBLE-02",
                        name="Double Extension (Decoy + Script)",
                        points=55,
                        description=f"File masquerades as a harmless '{decoy_extension}' document but actually executes as a '{real_extension}' script.",
                        details=f"Decoy extension: {decoy_extension} | True extension: {real_extension}"
                    ))
                    score += 55
                elif real_extension in self.shortcuts or norm_real_extension in self.shortcuts:
                    hits.append(RuleHit(
                        rule_id="RULE-DOUBLE-03",
                        name="Double Extension (Decoy + Shortcut/URL)",
                        points=50,
                        description=f"File masquerades as a harmless '{decoy_extension}' document but is a shortcut/link '{real_extension}' launcher.",
                        details=f"Decoy extension: {decoy_extension} | True extension: {real_extension}"
                    ))
                    score += 50
                elif real_extension in self.containers or norm_real_extension in self.containers:
                    hits.append(RuleHit(
                        rule_id="RULE-DOUBLE-04",
                        name="Double Extension (Decoy + Disk Container)",
                        points=45,
                        description=f"File uses a decoy '{decoy_extension}' naming scheme attached to a container '{real_extension}'.",
                        details=f"Decoy extension: {decoy_extension} | True extension: {real_extension}"
                    ))
                    score += 45
                else:
                    hits.append(RuleHit(
                        rule_id="RULE-DOUBLE-05",
                        name="Suspicious Multi-Part Extension",
                        points=30,
                        description=f"Multiple extensions detected including decoy '{decoy_extension}'.",
                        details=f"Extensions found: {' -> '.join(extensions)}"
                    ))
                    score += 30

        # 7. Standalone Risky Extensions (if not already heavily penalized by double ext)
        is_double_ext = any(h.rule_id.startswith("RULE-DOUBLE") for h in hits)
        if (real_extension in self.executables or norm_real_extension in self.executables) and not is_double_ext:
            hits.append(RuleHit(
                rule_id="RULE-EXE-01",
                name="High-Risk Executable Extension",
                points=45,
                description=f"Direct executable file type ({real_extension}). High risk in email attachment contexts.",
                details=f"Extension: {real_extension}"
            ))
            score += 45
        elif (real_extension in self.scripts or norm_real_extension in self.scripts) and not is_double_ext:
            hits.append(RuleHit(
                rule_id="RULE-SCRIPT-01",
                name="Executable Script Extension",
                points=35,
                description=f"Script file type ({real_extension}) that can execute commands when opened.",
                details=f"Extension: {real_extension}"
            ))
            score += 35
        elif real_extension in self.macro_office or norm_real_extension in self.macro_office:
            hits.append(RuleHit(
                rule_id="RULE-MACRO-01",
                name="Macro-Enabled Office Document",
                points=35,
                description=f"Macro-enabled document format ({real_extension}) capable of running VBA macro payloads.",
                details=f"Extension: {real_extension}"
            ))
            score += 35
        elif (real_extension in self.containers or norm_real_extension in self.containers) and not is_double_ext:
            hits.append(RuleHit(
                rule_id="RULE-CONTAINER-01",
                name="Disk Image / Container Format",
                points=35,
                description=f"Container/Disk image format ({real_extension}) frequently used to bypass Mark-of-the-Web (MOTW) protections.",
                details=f"Extension: {real_extension}"
            ))
            score += 35
        elif (real_extension in self.shortcuts or norm_real_extension in self.shortcuts) and not is_double_ext:
            hits.append(RuleHit(
                rule_id="RULE-SHORTCUT-01",
                name="Shortcut / Link File",
                points=40,
                description=f"Shortcut file ({real_extension}) that can execute embedded target commands.",
                details=f"Extension: {real_extension}"
            ))
            score += 40

        # 8. Excessive Filename Length (Obfuscation / Viewport Overflow)
        if len(basename) > 120:
            hits.append(RuleHit(
                rule_id="RULE-LENGTH-01",
                name="Excessive Filename Length",
                points=20,
                description=f"Filename is unusually long ({len(basename)} characters), often used to push true extensions outside client viewports.",
                details=f"Length: {len(basename)} chars"
            ))
            score += 20

        # Cap score at 100
        total_score = min(100, score)

        # Determine Verdict
        if total_score >= 60:
            verdict = ScanVerdict.HIGH
        elif total_score >= 25:
            verdict = ScanVerdict.MEDIUM
        else:
            verdict = ScanVerdict.LOW

        # File size if real file on disk
        file_size_bytes = None
        if filepath and os.path.exists(filepath):
            try:
                file_size_bytes = os.path.getsize(filepath)
            except OSError:
                pass

        sanitized_name = sanitize_unprintable(basename)
        visual_name = simulate_bidi_rendering(basename)

        return ScanResult(
            filename=basename,
            sanitized_name=sanitized_name,
            visual_name=visual_name,
            real_extension=real_extension,
            decoy_extension=decoy_extension,
            score=total_score,
            verdict=verdict,
            rule_hits=hits,
            filepath=filepath,
            file_size_bytes=file_size_bytes
        )

    def scan_file(self, filepath: str | Path) -> ScanResult:
        """Scans a physical file path."""
        path_obj = Path(filepath)
        return self.scan_filename(path_obj.name, filepath=str(path_obj.resolve()))

    def scan_directory(self, dirpath: str | Path, recursive: bool = False) -> List[ScanResult]:
        """Scans all files inside a directory."""
        path_obj = Path(dirpath)
        if not path_obj.is_dir():
            raise NotADirectoryError(f"Path is not a valid directory: {dirpath}")

        pattern = "**/*" if recursive else "*"
        results: List[ScanResult] = []
        for item in sorted(path_obj.glob(pattern)):
            if item.is_file():
                results.append(self.scan_file(item))
        # Rank by score descending
        results.sort(key=lambda r: r.score, reverse=True)
        return results

    def scan_list(self, filenames: Iterable[str]) -> List[ScanResult]:
        """Scans an iterable of filename strings."""
        results = [self.scan_filename(name.strip()) for name in filenames if name.strip()]
        results.sort(key=lambda r: r.score, reverse=True)
        return results


# -----------------------------------------------------------------------------
# Convenience Standalone Functions
# -----------------------------------------------------------------------------

_default_scanner = ChameleonScanner()


def scan_filename(name: str) -> ScanResult:
    """Convenience function to scan a single filename."""
    return _default_scanner.scan_filename(name)


def scan_directory(dirpath: str | Path, recursive: bool = False) -> List[ScanResult]:
    """Convenience function to scan a directory."""
    return _default_scanner.scan_directory(dirpath, recursive=recursive)


def scan_list(filenames: Iterable[str]) -> List[ScanResult]:
    """Convenience function to scan a list of filenames."""
    return _default_scanner.scan_list(filenames)


# -----------------------------------------------------------------------------
# Presentation and Reporting Formats
# -----------------------------------------------------------------------------

class Colors:
    """ANSI color codes for rich terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    @classmethod
    def strip(cls, text: str) -> str:
        return re.sub(r'\033\[[0-9;]*m', '', text)


def get_verdict_badge(verdict: ScanVerdict, use_color: bool = True) -> str:
    """Returns color-coded verdict badge."""
    if not use_color:
        return f"[{verdict.value}]"

    if verdict == ScanVerdict.HIGH:
        return f"{Colors.RED}{Colors.BOLD}[ HIGH ]{Colors.RESET}"
    elif verdict == ScanVerdict.MEDIUM:
        return f"{Colors.YELLOW}{Colors.BOLD}[MEDIUM]{Colors.RESET}"
    else:
        return f"{Colors.GREEN}{Colors.BOLD}[ LOW  ]{Colors.RESET}"


def format_table(
    results: List[ScanResult],
    verbose: bool = False,
    use_color: bool = True,
    show_summary: bool = True
) -> str:
    """Formats scan results into a polished, readable terminal table."""
    if not results:
        return "No files to scan."

    lines: List[str] = []

    # Header banner
    if use_color:
        banner = (
            f"\n{Colors.CYAN}{Colors.BOLD}[*] Chameleon Check v{__version__}{Colors.RESET} "
            f"{Colors.DIM}-- Email Attachment Deception Scanner{Colors.RESET}\n"
        )
    else:
        banner = f"\n=== Chameleon Check v{__version__} -- Email Attachment Deception Scanner ===\n"
    lines.append(banner)

    # Column widths
    w_name = 36
    w_real = 10
    w_decoy = 10
    w_score = 7
    w_verdict = 10

    # Header row
    hdr = f"{'FILENAME':<{w_name}}  {'REAL EXT':<{w_real}}  {'DECOY':<{w_decoy}}  {'SCORE':<{w_score}}  {'VERDICT':<{w_verdict}}  {'PRIMARY RED FLAGS'}"
    separator = "-" * len(hdr)
    if use_color:
        lines.append(f"{Colors.BOLD}{hdr}{Colors.RESET}")
        lines.append(f"{Colors.DIM}{separator}{Colors.RESET}")
    else:
        lines.append(hdr)
        lines.append(separator)

    # Result rows
    for r in results:
        # Truncate or sanitize filename for table column
        display_name = r.sanitized_name
        if len(display_name) > w_name:
            display_name = display_name[:w_name - 3] + "..."

        real_ext = r.real_extension or "none"
        decoy_ext = r.decoy_extension or "-"
        score_str = f"{r.score}/100"
        badge = get_verdict_badge(r.verdict, use_color=use_color)

        primary_flags = ", ".join(h.name for h in r.rule_hits[:2])
        if len(r.rule_hits) > 2:
            primary_flags += f" (+{len(r.rule_hits)-2} more)"
        if not primary_flags:
            primary_flags = "None detected (Benign)"

        row = (
            f"{display_name:<{w_name}}  "
            f"{real_ext:<{w_real}}  "
            f"{decoy_ext:<{w_decoy}}  "
            f"{score_str:<{w_score}}  "
            f"{badge:<{w_verdict}}  "
            f"{primary_flags}"
        )
        lines.append(row)

        # Verbose breakdown
        if verbose:
            indent = "    "
            if r.visual_name != r.filename:
                lines.append(f"{indent}{Colors.MAGENTA if use_color else ''}--> Visual UI Display : {r.visual_name}{Colors.RESET if use_color else ''}")
            if r.rule_hits:
                for hit in r.rule_hits:
                    hit_color = Colors.RED if hit.points >= 50 else (Colors.YELLOW if hit.points >= 30 else Colors.BLUE)
                    col = hit_color if use_color else ""
                    rst = Colors.RESET if use_color else ""
                    lines.append(f"{indent}  {col}[+{hit.points:02d} pts] {hit.name}{rst}: {hit.description}")
                    if hit.details:
                        lines.append(f"{indent}             Details: {hit.details}")
            lines.append("")

    # Summary statistics
    if show_summary:
        total = len(results)
        highs = sum(1 for r in results if r.verdict == ScanVerdict.HIGH)
        mediums = sum(1 for r in results if r.verdict == ScanVerdict.MEDIUM)
        lows = sum(1 for r in results if r.verdict == ScanVerdict.LOW)

        sum_line = (
            f"\n{separator}\n"
            f"Scan Summary: Total Scanned: {total} | "
            f"{(Colors.RED if use_color else '')}HIGH: {highs}{(Colors.RESET if use_color else '')} | "
            f"{(Colors.YELLOW if use_color else '')}MEDIUM: {mediums}{(Colors.RESET if use_color else '')} | "
            f"{(Colors.GREEN if use_color else '')}LOW: {lows}{(Colors.RESET if use_color else '')}"
        )
        lines.append(sum_line)

    return "\n".join(lines)


def to_json(results: List[ScanResult], indent: int = 2) -> str:
    """Serializes scan results to JSON."""
    data = {
        "tool": __tool_name__,
        "version": __version__,
        "total_scanned": len(results),
        "verdict_counts": {
            "HIGH": sum(1 for r in results if r.verdict == ScanVerdict.HIGH),
            "MEDIUM": sum(1 for r in results if r.verdict == ScanVerdict.MEDIUM),
            "LOW": sum(1 for r in results if r.verdict == ScanVerdict.LOW),
        },
        "results": [r.to_dict() for r in results]
    }
    return json.dumps(data, indent=indent)


def to_csv(results: List[ScanResult]) -> str:
    """Serializes scan results to CSV."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Filename", "SanitizedName", "Verdict", "Score", "RealExtension", "DecoyExtension", "RuleCount", "RulesTriggered", "FilePath"])
    for r in results:
        rules_str = "; ".join(h.rule_id for h in r.rule_hits)
        writer.writerow([
            r.filename,
            r.sanitized_name,
            r.verdict.value,
            r.score,
            r.real_extension,
            r.decoy_extension or "",
            len(r.rule_hits),
            rules_str,
            r.filepath or ""
        ])
    return output.getvalue()


# -----------------------------------------------------------------------------
# CLI Entrypoint
# -----------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chameleon_check",
        description="Chameleon Check: Spot disguised and risky email attachments before they fool anyone.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  chameleon_check --file invoice.pdf.exe
  chameleon_check --dir ./attachments --recursive
  chameleon_check --names "statement.xlsx.vbs" "contract.pdf" "photo.jpg.scr"
  chameleon_check --file-list emails_attachments.txt --json
  echo "salary_sheet.pdf.exe" | chameleon_check -
  chameleon_check --dir ./inbox --fail-on-high
        """
    )

    group = parser.add_argument_group("Scan Targets (Specify at least one)")
    group.add_argument(
        "positional_target",
        nargs="?",
        default=None,
        help="Optional single filename, file path, directory, or '-' for stdin"
    )
    group.add_argument("-f", "--file", dest="file_target", help="Scan a single file or filename")
    group.add_argument("-d", "--dir", dest="dir_target", help="Scan all files in a directory")
    group.add_argument("-n", "--names", nargs="+", help="Scan a list of filenames directly")
    group.add_argument("-l", "--file-list", help="Scan filenames listed in a text file (one per line)")

    opts = parser.add_argument_group("Scan Options")
    opts.add_argument("-r", "--recursive", action="store_true", help="Recursively scan subdirectories when using --dir")
    opts.add_argument("-m", "--min-verdict", choices=["LOW", "MEDIUM", "HIGH"], default="LOW", help="Filter display to only show results at or above this verdict (default: LOW)")
    opts.add_argument("-v", "--verbose", action="store_true", help="Show detailed breakdown of triggered detection rules and points")

    output_group = parser.add_argument_group("Output Formats")
    output_group.add_argument("--json", action="store_true", help="Output results in JSON format")
    output_group.add_argument("--csv", action="store_true", help="Output results in CSV format")
    output_group.add_argument("-o", "--output", help="Save output directly to specified file path (.json, .csv, or .txt)")
    output_group.add_argument("--no-color", action="store_true", help="Disable ANSI color output in terminal")

    pipeline_group = parser.add_argument_group("Pipeline & CI/CD Integration")
    pipeline_group.add_argument("--fail-on-high", action="store_true", help="Exit with code 1 if any HIGH risk attachment is detected")
    pipeline_group.add_argument("--fail-on-medium", action="store_true", help="Exit with code 1 if any MEDIUM or HIGH risk attachment is detected")

    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    scanner = ChameleonScanner()
    raw_results: List[ScanResult] = []

    # Determine input sources
    targets_processed = False

    # 1. Positional argument handling
    if args.positional_target:
        if args.positional_target == "-":
            # Stdin pipe
            stdin_content = sys.stdin.read().splitlines()
            raw_results.extend(scanner.scan_list(stdin_content))
            targets_processed = True
        elif os.path.isdir(args.positional_target):
            raw_results.extend(scanner.scan_directory(args.positional_target, recursive=args.recursive))
            targets_processed = True
        else:
            raw_results.append(scanner.scan_file(args.positional_target) if os.path.exists(args.positional_target) else scanner.scan_filename(args.positional_target))
            targets_processed = True

    # 2. File argument
    if args.file_target:
        if os.path.exists(args.file_target):
            raw_results.append(scanner.scan_file(args.file_target))
        else:
            raw_results.append(scanner.scan_filename(args.file_target))
        targets_processed = True

    # 3. Directory argument
    if args.dir_target:
        raw_results.extend(scanner.scan_directory(args.dir_target, recursive=args.recursive))
        targets_processed = True

    # 4. Direct list of names
    if args.names:
        raw_results.extend(scanner.scan_list(args.names))
        targets_processed = True

    # 5. File list
    if args.file_list:
        with open(args.file_list, "r", encoding="utf-8", errors="replace") as f:
            lines = [line.strip() for line in f if line.strip()]
        raw_results.extend(scanner.scan_list(lines))
        targets_processed = True

    # If no target specified and stdin is piped
    if not targets_processed:
        if not sys.stdin.isatty():
            stdin_content = sys.stdin.read().splitlines()
            raw_results.extend(scanner.scan_list(stdin_content))
            targets_processed = True
        else:
            parser.print_help()
            return 1

    # Sort results by score descending
    raw_results.sort(key=lambda r: r.score, reverse=True)

    # Filter by minimum verdict if requested
    verdict_hierarchy = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
    min_rank = verdict_hierarchy[args.min_verdict]
    filtered_results = [r for r in raw_results if verdict_hierarchy[r.verdict.value] >= min_rank]

    # Format output
    use_color = not args.no_color and sys.stdout.isatty() and not args.json and not args.csv

    if args.json or (args.output and args.output.lower().endswith(".json")):
        formatted_output = to_json(filtered_results)
    elif args.csv or (args.output and args.output.lower().endswith(".csv")):
        formatted_output = to_csv(filtered_results)
    else:
        formatted_output = format_table(filtered_results, verbose=args.verbose, use_color=use_color)

    # Save to file or print to stdout
    if args.output:
        # Strip ANSI if saving text report to file
        save_text = Colors.strip(formatted_output) if not args.json and not args.csv else formatted_output
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(save_text + "\n")
        print(f"Results saved successfully to {args.output}")
    else:
        print(formatted_output)

    # Exit code evaluation for pipelines
    has_high = any(r.verdict == ScanVerdict.HIGH for r in raw_results)
    has_medium = any(r.verdict == ScanVerdict.MEDIUM for r in raw_results)

    if args.fail_on_high and has_high:
        return 1
    if args.fail_on_medium and (has_high or has_medium):
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
