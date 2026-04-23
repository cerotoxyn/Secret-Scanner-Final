"""
Secret Scanner CLI
Scans files or directories for possible hardcoded secrets using regex patterns.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List


@dataclass
class Finding:
    pattern_name: str
    file_path: str
    line_number: int
    matched_text: str


# Minimum 5 patterns from the assignment resource, plus a generic private key pattern.
PATTERNS = {
    "GitHub Personal Access Token (classic)": re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    "GitHub Fine-Grained PAT": re.compile(r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b"),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "Slack Bot Token": re.compile(r"\bxoxb-[0-9]{11}-[0-9]{11}-[0-9A-Za-z]{24}\b"),
    "Stripe Standard API Key": re.compile(r"\bsk_live_[0-9A-Za-z]{24}\b"),
    "AWS Access Key ID": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "OpenAI User API Key": re.compile(r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b"),
    "Mailgun API Key": re.compile(r"\bkey-[0-9A-Za-z]{32}\b"),
    "Twitter Access Token": re.compile(r"\b[1-9][0-9]+-[0-9A-Za-z]{40}\b"),
    "Private Key Block": re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
}

# Common text/code file extensions to scan
TEXT_FILE_EXTENSIONS = {
    ".py", ".js", ".ts", ".java", ".c", ".cpp", ".cs", ".go", ".rb", ".php",
    ".env", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".txt", ".md", ".xml", ".html", ".css", ".sh", ".ps1"
}


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s"
    )


def is_text_candidate(path: Path) -> bool:
    if path.suffix.lower() in TEXT_FILE_EXTENSIONS:
        return True
    # Also allow extensionless files like ".env" alternatives or config files
    return path.suffix == ""


def iter_files(target: Path) -> Iterable[Path]:
    if target.is_file():
        yield target
        return

    for root, _, files in os.walk(target):
        for filename in files:
            file_path = Path(root) / filename
            if is_text_candidate(file_path):
                yield file_path


def mask_secret(secret: str, keep_start: int = 4, keep_end: int = 4) -> str:
    """
    Mask the matched secret so the report does not fully expose it.
    """
    if len(secret) <= keep_start + keep_end:
        return "*" * len(secret)
    return f"{secret[:keep_start]}{'*' * (len(secret) - keep_start - keep_end)}{secret[-keep_end:]}"


def scan_file(file_path: Path) -> List[Finding]:
    findings: List[Finding] = []

    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                for pattern_name, pattern in PATTERNS.items():
                    for match in pattern.finditer(line):
                        findings.append(
                            Finding(
                                pattern_name=pattern_name,
                                file_path=str(file_path),
                                line_number=line_number,
                                matched_text=mask_secret(match.group(0)),
                            )
                        )
    except Exception as exc:
        logging.warning("Could not scan %s: %s", file_path, exc)

    return findings


def print_report(findings: List[Finding]) -> None:
    if not findings:
        print("No potential secrets found.")
        return

    print("\nPotential secrets found:\n")
    for finding in findings:
        print(
            f"[{finding.pattern_name}] "
            f"{finding.file_path}:{finding.line_number} -> {finding.matched_text}"
        )

    print(f"\nTotal findings: {len(findings)}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan a file or directory for possible hardcoded secrets."
    )
    parser.add_argument(
        "target",
        help="Path to a file or directory to scan"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    setup_logging(args.verbose)

    target = Path(args.target)

    if not target.exists():
        logging.error("Target does not exist: %s", target)
        return 1

    logging.info("Scanning target: %s", target)

    all_findings: List[Finding] = []

    for file_path in iter_files(target):
        logging.debug("Scanning file: %s", file_path)
        all_findings.extend(scan_file(file_path))

    print_report(all_findings)
    return 0


if __name__ == "__main__":
    sys.exit(main())