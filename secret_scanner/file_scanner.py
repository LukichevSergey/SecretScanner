"""
File system scanner module.
Performs high-performance concurrent scanning of source files, configuration assets,
and sensitive binary artifacts.
"""

import os
import re
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional, Tuple

from secret_scanner.config import ScannerConfig
from secret_scanner.entropy import extract_high_entropy_candidates
from secret_scanner.models import Finding, MatchContext, PatternRule, RiskLevel
from secret_scanner.patterns import resolve_active_rules
from secret_scanner.utils import extract_context, is_binary_file, redact_secret

# Special sensitive file names & extensions requiring special auditing
SENSITIVE_FILENAME_RULES = [
    (re.compile(r"GoogleService-Info\.plist$", re.I), RiskLevel.HIGH, "GoogleService-Info.plist", "Google Cloud / Firebase configuration file containing API keys and database endpoints."),
    (re.compile(r"\.p8$", re.I), RiskLevel.CRITICAL, "Apple p8 Private Key File", "Apple Developer authentication key used for APNs or App Store Connect API."),
    (re.compile(r"\.mobileprovision$", re.I), RiskLevel.MEDIUM, "Provisioning Profile", "Apple Provisioning Profile file containing certificate and device identifiers."),
    (re.compile(r"\.(?:p12|pfx)$", re.I), RiskLevel.CRITICAL, "PKCS#12 KeyStore", "PKCS#12 certificate and private key store."),
    (re.compile(r"\.(?:pem|crt|key|keystore)$", re.I), RiskLevel.HIGH, "Certificate or Private Key File", "Cryptographic key or certificate file."),
    (re.compile(r"^id_(?:rsa|ed25519|dsa)(?:\.pub)?$", re.I), RiskLevel.CRITICAL, "SSH Private Key File", "SSH private key file."),
    (re.compile(r"^known_hosts$", re.I), RiskLevel.LOW, "SSH Known Hosts", "Known hosts file detailing remote server host keys."),
    (re.compile(r"\.(?:sqlite|sqlite3|db|realm)$", re.I), RiskLevel.MEDIUM, "Database File", "Local SQLite or Realm database file which may contain sensitive offline user data."),
    (re.compile(r"\.(?:log|crash)$", re.I), RiskLevel.LOW, "Log or Crash Report File", "Application log or crash dump file containing runtime state."),
    (re.compile(r"service-account.*\.json$", re.I), RiskLevel.CRITICAL, "GCP Service Account Key JSON", "Google Cloud Platform service account key JSON credentials."),
    (re.compile(r"credentials\.json$", re.I), RiskLevel.HIGH, "Service Credentials JSON", "Authentication credentials file."),
]


def compile_rules(config: ScannerConfig) -> List[Tuple[PatternRule, "re.Pattern"]]:
    """
    Compile the active rule set once so it can be reused for every scanned file.

    Rules whose regex fails to compile (e.g. a malformed user-supplied pattern)
    are skipped rather than aborting the scan.
    """
    compiled: List[Tuple[PatternRule, re.Pattern]] = []
    for rule in resolve_active_rules(config):
        try:
            compiled.append((rule, re.compile(rule.pattern)))
        except Exception:
            continue
    return compiled


def scan_single_file(
    file_path_str: str,
    config: ScannerConfig,
    compiled_rules: Optional[List[Tuple[PatternRule, "re.Pattern"]]] = None,
) -> Tuple[List[Finding], int, int]:
    """
    Scan a single file for secret patterns, entropy candidates, and filename risks.

    Args:
        file_path_str: Absolute path string to target file.
        config: ScannerConfig configuration settings.
        compiled_rules: Pre-compiled rules shared across files; built on demand if omitted.

    Returns:
        Tuple containing (List of Findings, 1 if file scanned else 0, total lines in file).
    """
    file_path = Path(file_path_str)
    rel_path = str(file_path.relative_to(config.project_path)) if file_path.is_relative_to(config.project_path) else str(file_path)
    findings: List[Finding] = []

    # 1. Audit filename risks first
    for fn_regex, risk, fn_type, fn_desc in SENSITIVE_FILENAME_RULES:
        if fn_regex.search(file_path.name):
            findings.append(
                Finding(
                    finding_type=fn_type,
                    risk_level=risk,
                    description=fn_desc,
                    file_path=rel_path,
                    line_number=1,
                    matched_string=file_path.name,
                    recommendation="Ensure this file is listed in .gitignore and not uploaded to remote repositories.",
                    context=MatchContext(line_content=f"File: {file_path.name}", line_number=1),
                    rule_id="FILE-AUDIT",
                )
            )
            break

    # 2. Check if binary file
    if is_binary_file(file_path):
        return findings, 1, 0

    # 3. Read file lines safely
    lines: List[str] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return findings, 1, 0

    line_count = len(lines)
    if compiled_rules is None:
        compiled_rules = compile_rules(config)

    # 4. Scan content line by line
    for idx, line in enumerate(lines):
        line_num = idx + 1

        # Check pattern rules
        for rule, compiled_regex in compiled_rules:
            # If rule has file_patterns filter, test applicability
            if rule.file_patterns:
                matched_pattern = any(
                    file_path.name == fp or file_path.name.endswith(fp.lstrip("*"))
                    for fp in rule.file_patterns
                )
                if not matched_pattern:
                    continue

            # Evaluate regex
            for match in compiled_regex.finditer(line):
                matched_str = match.group(0)
                context = extract_context(lines, idx, config.context_lines)
                
                findings.append(
                    Finding(
                        finding_type=rule.name,
                        risk_level=rule.risk_level,
                        description=rule.description,
                        file_path=rel_path,
                        line_number=line_num,
                        matched_string=redact_secret(matched_str),
                        recommendation=rule.recommendation,
                        context=context,
                        rule_id=rule.id,
                    )
                )

        # Check entropy candidates
        if config.enable_entropy:
            candidates = extract_high_entropy_candidates(
                line=line,
                min_length=config.min_entropy_length,
                entropy_threshold=config.entropy_threshold,
            )
            for cand, entropy_val in candidates:
                context = extract_context(lines, idx, config.context_lines)
                findings.append(
                    Finding(
                        finding_type="High Entropy String (Possible Secret)",
                        risk_level=RiskLevel.MEDIUM,
                        description=f"Detected high Shannon entropy string ({entropy_val:.2f} bits/char).",
                        file_path=rel_path,
                        line_number=line_num,
                        matched_string=redact_secret(cand),
                        recommendation="Verify if this string represents a secret key, auth token, or encryption key.",
                        context=context,
                        entropy=round(entropy_val, 2),
                        rule_id="ENTROPY-001",
                    )
                )

    return findings, 1, line_count


def collect_target_files(config: ScannerConfig) -> List[Path]:
    """
    Collect all eligible files from target project directory according to config exclusions.
    
    Args:
        config: ScannerConfig settings.

    Returns:
        List of Path objects representing files to scan.
    """
    target_files: List[Path] = []
    root = config.project_path

    if not root.exists():
        return target_files

    if root.is_file():
        return [root]

    for dirpath, dirnames, filenames in os.walk(root):
        # Filter excluded directories in-place
        dirnames[:] = [
            d for d in dirnames
            if d not in config.excluded_dirs
            and not d.startswith(".")
            and not d.endswith(".xcodeproj")
            and not d.endswith(".xcworkspace")
        ]

        for fname in filenames:
            if fname in config.excluded_files or fname.startswith(".DS_Store"):
                continue

            fpath = Path(dirpath) / fname
            
            # Match extension or exact filename or sensitive filename rule
            ext = fpath.suffix.lower()
            if (
                ext in config.included_extensions
                or fname in config.exact_filenames
                or any(fn_regex.search(fname) for fn_regex, _, _, _ in SENSITIVE_FILENAME_RULES)
            ):
                target_files.append(fpath)

    return target_files


def scan_files(config: ScannerConfig) -> Tuple[List[Finding], int, int]:
    """
    Multithreaded filesystem scanner executor.
    
    Args:
        config: ScannerConfig settings.

    Returns:
        Tuple containing (all Findings, total files scanned, total lines scanned).
    """
    files_to_scan = collect_target_files(config)
    all_findings: List[Finding] = []
    total_files = 0
    total_lines = 0

    if not files_to_scan:
        return all_findings, 0, 0

    workers = max(1, min(config.max_workers, len(files_to_scan)))

    # Compile the rule set once and share it across all worker threads
    compiled_rules = compile_rules(config)

    # Use ThreadPoolExecutor for IO bound file operations
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_file = {
            executor.submit(scan_single_file, str(fpath), config, compiled_rules): fpath
            for fpath in files_to_scan
        }

        for future in as_completed(future_to_file):
            try:
                findings, file_count, line_count = future.result()
                all_findings.extend(findings)
                total_files += file_count
                total_lines += line_count
            except Exception as err:
                fpath = future_to_file[future]
                print(f"Error scanning file {fpath}: {err}")

    return all_findings, total_files, total_lines
