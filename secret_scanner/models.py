"""
Core data models and type definitions for SecretScanner.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class RiskLevel(str, Enum):
    """Enumeration of risk levels for detected findings."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

    @property
    def severity_score(self) -> int:
        """Numerical score for sorting findings by severity."""
        scores = {
            RiskLevel.CRITICAL: 5,
            RiskLevel.HIGH: 4,
            RiskLevel.MEDIUM: 3,
            RiskLevel.LOW: 2,
            RiskLevel.INFO: 1,
        }
        return scores[self]

    @property
    def color_code(self) -> str:
        """ANSI color code string for console output formatting."""
        colors = {
            RiskLevel.CRITICAL: "\033[1;31m",  # Bold Red
            RiskLevel.HIGH: "\033[0;31m",      # Red
            RiskLevel.MEDIUM: "\033[0;33m",    # Yellow
            RiskLevel.LOW: "\033[0;36m",       # Cyan
            RiskLevel.INFO: "\033[0;37m",      # White
        }
        return colors[self]


@dataclass
class MatchContext:
    """Surrounding context lines for a detected secret (20 lines before/after)."""
    lines_before: List[str] = field(default_factory=list)
    line_content: str = ""
    line_number: int = 0
    lines_after: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "lines_before": self.lines_before,
            "line_content": self.line_content,
            "line_number": self.line_number,
            "lines_after": self.lines_after,
        }


@dataclass
class PatternRule:
    """Definition of a regex pattern rule for identifying secrets."""
    id: str
    name: str
    pattern: str
    risk_level: RiskLevel
    description: str
    recommendation: str
    file_patterns: Optional[List[str]] = None
    is_swift_rule: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "pattern": self.pattern,
            "risk_level": self.risk_level.value,
            "description": self.description,
            "recommendation": self.recommendation,
            "file_patterns": self.file_patterns,
            "is_swift_rule": self.is_swift_rule,
        }


@dataclass
class Finding:
    """Represents a detected secret or security issue found during audit."""
    finding_type: str
    risk_level: RiskLevel
    description: str
    file_path: str
    line_number: int
    matched_string: str
    recommendation: str
    context: MatchContext
    commit_hash: Optional[str] = None
    author: Optional[str] = None
    date: Optional[str] = None
    entropy: Optional[float] = None
    rule_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding into dictionary for JSON serialization."""
        return {
            "finding_type": self.finding_type,
            "risk_level": self.risk_level.value,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "matched_string": self.matched_string,
            "recommendation": self.recommendation,
            "context": self.context.to_dict(),
            "commit_hash": self.commit_hash,
            "author": self.author,
            "date": self.date,
            "entropy": self.entropy,
            "rule_id": self.rule_id,
        }


@dataclass
class ScanStats:
    """Statistics collected during scan execution."""
    files_scanned: int = 0
    lines_scanned: int = 0
    total_findings: int = 0
    suspicious_lines: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    elapsed_time_seconds: float = 0.0

    def update_with_findings(self, findings: List[Finding]) -> None:
        """Update statistics based on a list of findings."""
        self.total_findings = len(findings)
        self.suspicious_lines = len({(f.file_path, f.line_number) for f in findings})
        self.critical_count = sum(1 for f in findings if f.risk_level == RiskLevel.CRITICAL)
        self.high_count = sum(1 for f in findings if f.risk_level == RiskLevel.HIGH)
        self.medium_count = sum(1 for f in findings if f.risk_level == RiskLevel.MEDIUM)
        self.low_count = sum(1 for f in findings if f.risk_level == RiskLevel.LOW)
        self.info_count = sum(1 for f in findings if f.risk_level == RiskLevel.INFO)

    def to_dict(self) -> Dict[str, Any]:
        """Convert statistics to dictionary."""
        return {
            "files_scanned": self.files_scanned,
            "lines_scanned": self.lines_scanned,
            "total_findings": self.total_findings,
            "suspicious_lines": self.suspicious_lines,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "elapsed_time_seconds": round(self.elapsed_time_seconds, 3),
        }


@dataclass
class ScannerConfig:
    """Configuration options controlling scanner behavior."""
    project_path: Path
    excluded_dirs: Set[str] = field(default_factory=lambda: {
        "DerivedData", ".build", ".git", "Pods", "Carthage",
        "node_modules", "vendor", "dist", "build", ".venv", "venv",
        "__pycache__", ".xcodeproj", ".xcworkspace", ".swiftpm"
    })
    excluded_files: Set[str] = field(default_factory=lambda: {
        ".DS_Store", "package-lock.json", "yarn.lock", "Podfile.lock",
        "Cartfile.resolved", "Package.resolved"
    })
    included_extensions: Set[str] = field(default_factory=lambda: {
        ".swift", ".h", ".m", ".mm", ".c", ".cpp", ".hpp", ".json",
        ".yaml", ".yml", ".toml", ".xml", ".plist", ".env", ".xcconfig",
        ".rb", ".sh", ".bash", ".zsh", ".properties", ".txt", ".md",
        ".sql", ".gradle", ".kts", ".entitlements", ".py"
    })
    exact_filenames: Set[str] = field(default_factory=lambda: {
        "Podfile", "Package.swift", "Cartfile", "Gemfile", "Fastfile",
        "Appfile", "Matchfile", "GoogleService-Info.plist", "firebase.json",
        "docker-compose.yml", "docker-compose.yaml", "credentials.json",
        "service-account.json"
    })
    enable_entropy: bool = True
    entropy_threshold: float = 4.5
    min_entropy_length: int = 20
    enable_git: bool = True
    max_workers: int = 8
    context_lines: int = 20
    generate_html: bool = True
    generate_json: bool = True
    generate_markdown: bool = True
    generate_text: bool = True



@dataclass
class ScanReport:
    """Complete audit report artifact."""
    stats: ScanStats
    findings: List[Finding]
    scanned_path: str
    scan_timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert entire report to dictionary."""
        return {
            "scanned_path": self.scanned_path,
            "scan_timestamp": self.scan_timestamp,
            "stats": self.stats.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
        }
