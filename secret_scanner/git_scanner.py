"""
Git history scanner module.
Audits commit history, git stash, deleted files, tags, and uncommitted diffs for secrets.
"""

import re
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from secret_scanner.config import ScannerConfig
from secret_scanner.entropy import extract_high_entropy_candidates
from secret_scanner.models import Finding, MatchContext, RiskLevel
from secret_scanner.patterns import get_all_rules
from secret_scanner.utils import redact_secret


def is_git_repository(repo_path: Path) -> bool:
    """Check if target directory is inside a valid Git repository."""
    git_dir = repo_path / ".git"
    if git_dir.exists():
        return True
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=repo_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        return res.returncode == 0 and "true" in res.stdout.lower()
    except Exception:
        return False


def run_git_command(args: List[str], cwd: Path) -> Optional[str]:
    """Execute a git CLI command safely and return output."""
    try:
        res = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=120,
        )
        if res.returncode == 0:
            return res.stdout
    except Exception as err:
        print(f"Warning: Git command failed ({' '.join(args)}): {err}")
    return None


def scan_git_history(config: ScannerConfig) -> List[Finding]:
    """
    Perform deep security audit of Git repository (commits, stashes, deleted files, diffs).
    
    Args:
        config: ScannerConfig settings.

    Returns:
        List of Finding objects detected in Git history.
    """
    repo_path = config.project_path
    if not config.enable_git or not is_git_repository(repo_path):
        return []

    findings: List[Finding] = []
    rules = get_all_rules()
    compiled_rules = [(rule, re.compile(rule.pattern)) for rule in rules]

    # 1. Audit Git commit log diffs across all commits, branches, and tags
    git_log_output = run_git_command(
        ["log", "--all", "-p", "--full-history", "--no-merges", "-U3", "--format=COMMIT:%H|%an|%ad"],
        cwd=repo_path,
    )

    if git_log_output:
        current_commit = "HEAD"
        current_author = "Unknown"
        current_date = "Unknown"
        current_file = "Unknown"

        log_lines = git_log_output.splitlines()
        for idx, line in enumerate(log_lines):
            if line.startswith("COMMIT:"):
                parts = line[7:].split("|")
                if len(parts) >= 3:
                    current_commit = parts[0][:8]
                    current_author = parts[1]
                    current_date = parts[2]
                continue

            if line.startswith("--- a/") or line.startswith("+++ b/"):
                current_file = line[6:].strip()
                continue

            # Only scan added lines in diffs
            if line.startswith("+") and not line.startswith("+++"):
                added_line = line[1:]

                # Check pattern rules
                for rule, compiled_regex in compiled_rules:
                    for match in compiled_regex.finditer(added_line):
                        matched_str = match.group(0)
                        findings.append(
                            Finding(
                                finding_type=f"Git History: {rule.name}",
                                risk_level=rule.risk_level,
                                description=f"{rule.description} (Found in Git commit {current_commit})",
                                file_path=current_file,
                                line_number=1,
                                matched_string=redact_secret(matched_str),
                                recommendation=rule.recommendation,
                                context=MatchContext(
                                    lines_before=[],
                                    line_content=added_line,
                                    line_number=1,
                                    lines_after=[],
                                ),
                                commit_hash=current_commit,
                                author=current_author,
                                date=current_date,
                                rule_id=f"GIT-{rule.id}",
                            )
                        )

                # Check entropy
                if config.enable_entropy:
                    candidates = extract_high_entropy_candidates(
                        line=added_line,
                        min_length=config.min_entropy_length,
                        entropy_threshold=config.entropy_threshold,
                    )
                    for cand, entropy_val in candidates:
                        findings.append(
                            Finding(
                                finding_type="Git History: High Entropy String",
                                risk_level=RiskLevel.MEDIUM,
                                description=f"High entropy string in commit {current_commit} ({entropy_val:.2f} bits/char).",
                                file_path=current_file,
                                line_number=1,
                                matched_string=redact_secret(cand),
                                recommendation="Purge secret from Git history using BFG Repo-Cleaner or git filter-repo.",
                                context=MatchContext(
                                    lines_before=[],
                                    line_content=added_line,
                                    line_number=1,
                                    lines_after=[],
                                ),
                                commit_hash=current_commit,
                                author=current_author,
                                date=current_date,
                                entropy=round(entropy_val, 2),
                                rule_id="GIT-ENTROPY",
                            )
                        )

    # 2. Audit Git Stash entries
    stash_list_output = run_git_command(["stash", "list"], cwd=repo_path)
    if stash_list_output:
        stashes = stash_list_output.splitlines()
        for stash_line in stashes:
            stash_id = stash_line.split(":")[0].strip() if ":" in stash_line else "stash@{0}"
            stash_diff = run_git_command(["stash", "show", "-p", stash_id], cwd=repo_path)
            if not stash_diff:
                continue

            s_file = "Stash Diff"
            for s_line in stash_diff.splitlines():
                if s_line.startswith("+++ b/"):
                    s_file = s_line[6:].strip()
                    continue
                if s_line.startswith("+") and not s_line.startswith("+++"):
                    added = s_line[1:]
                    for rule, compiled_regex in compiled_rules:
                        for match in compiled_regex.finditer(added):
                            matched_str = match.group(0)
                            findings.append(
                                Finding(
                                    finding_type=f"Git Stash: {rule.name}",
                                    risk_level=rule.risk_level,
                                    description=f"{rule.description} (Found in {stash_id})",
                                    file_path=s_file,
                                    line_number=1,
                                    matched_string=redact_secret(matched_str),
                                    recommendation="Clear Git stash entries containing secrets (`git stash drop`).",
                                    context=MatchContext(line_content=added, line_number=1),
                                    commit_hash=stash_id,
                                    rule_id=f"STASH-{rule.id}",
                                )
                            )

    return findings
