"""
JSON Report Generator for SecretScanner.
Outputs structured machine-readable scan results.
"""

from __future__ import annotations

import json
from pathlib import Path
from secret_scanner.models import ScanReport



def generate_json_report(report: ScanReport, output_path: Path | str) -> Path:
    """
    Generate report.json file from ScanReport object.
    
    Args:
        report: ScanReport data model.
        output_path: Path where report.json should be saved.

    Returns:
        Path object pointing to saved JSON file.
    """
    out_file = Path(output_path)
    report_dict = report.to_dict()

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2, ensure_ascii=False)

    return out_file
