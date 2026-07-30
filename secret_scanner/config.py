"""
Configuration management for SecretScanner.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Set
from secret_scanner.models import ScannerConfig



def default_config(project_path: Path | str) -> ScannerConfig:
    """Create a default ScannerConfig object for the target directory."""
    path = Path(project_path).resolve()
    return ScannerConfig(project_path=path)


def load_config_from_file(config_path: Path | str, target_project_path: Path | str) -> ScannerConfig:
    """
    Load scanner configuration from a JSON file, overriding defaults.
    
    Args:
        config_path: Path to the configuration JSON file.
        target_project_path: Target directory to scan.

    Returns:
        ScannerConfig instance populated from file.
    """
    cfg_file = Path(config_path)
    base_cfg = default_config(target_project_path)

    if not cfg_file.exists():
        return base_cfg

    try:
        with open(cfg_file, "r", encoding="utf-8") as f:
            data: Dict[str, Any] = json.load(f)

        if "excluded_dirs" in data and isinstance(data["excluded_dirs"], list):
            base_cfg.excluded_dirs.update(data["excluded_dirs"])

        if "excluded_files" in data and isinstance(data["excluded_files"], list):
            base_cfg.excluded_files.update(data["excluded_files"])

        if "included_extensions" in data and isinstance(data["included_extensions"], list):
            base_cfg.included_extensions.update(data["included_extensions"])

        if "enable_entropy" in data and isinstance(data["enable_entropy"], bool):
            base_cfg.enable_entropy = data["enable_entropy"]

        if "entropy_threshold" in data and isinstance(data["entropy_threshold"], (int, float)):
            base_cfg.entropy_threshold = float(data["entropy_threshold"])

        if "min_entropy_length" in data and isinstance(data["min_entropy_length"], int):
            base_cfg.min_entropy_length = data["min_entropy_length"]

        if "enable_git" in data and isinstance(data["enable_git"], bool):
            base_cfg.enable_git = data["enable_git"]

        if "max_workers" in data and isinstance(data["max_workers"], int):
            base_cfg.max_workers = data["max_workers"]

        if "context_lines" in data and isinstance(data["context_lines"], int):
            base_cfg.context_lines = data["context_lines"]

    except Exception as err:
        print(f"Warning: Failed to load config from {cfg_file}: {err}. Using defaults.")

    return base_cfg
