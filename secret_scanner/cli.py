"""
Command Line Interface (CLI) module for SecretScanner.
Supports CLI positional arguments and GUI folder picker dialog fallback via Tkinter.
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

from secret_scanner.config import load_config_from_file
from secret_scanner.scanner import SecretScannerEngine


def prompt_folder_dialog() -> Optional[Path]:
    """
    Open standard Tkinter GUI directory selection dialog.
    
    Returns:
        Path object if directory was chosen, or None.
    """
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()  # Hide root window
        root.attributes("-topmost", True)  # Bring file picker to front
        
        folder_selected = filedialog.askdirectory(title="Select Project Directory to Audit")
        root.destroy()

        if folder_selected:
            return Path(folder_selected)
    except Exception as err:
        print(f"Tkinter GUI file picker not available: {err}")

    return None


def main() -> int:
    """CLI entry point function."""
    parser = argparse.ArgumentParser(
        description="SecretScanner - Production iOS/macOS & Cross-platform Secret Audit Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Path to project directory (opens Desktop GUI if omitted)",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch native Desktop GUI application",
    )
    parser.add_argument(
        "--config",
        "-c",
        type=str,
        default=None,
        help="Path to custom JSON configuration file",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=str,
        default=None,
        help="Directory where generated reports (report.html, json, md, txt) will be saved",
    )
    parser.add_argument(
        "--no-git",
        action="store_true",
        help="Disable scanning Git history and commit diffs",
    )
    parser.add_argument(
        "--no-entropy",
        action="store_true",
        help="Disable Shannon entropy secret detection",
    )
    parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=4.5,
        help="Shannon entropy threshold cutoff value (0.0 - 8.0)",
    )
    parser.add_argument(
        "--workers",
        "-w",
        type=int,
        default=8,
        help="Number of concurrent worker threads",
    )

    args = parser.parse_args()

    # Launch GUI if requested or if no positional path argument is supplied
    if args.gui or (not args.path and sys.stdin.isatty()):
        try:
            from secret_scanner.gui import launch_gui
            launch_gui()
            return 0
        except Exception as err:
            print(f"Notice: Desktop GUI could not be initialized ({err}). Falling back to CLI mode...")

    # Determine target project path
    target_path: Optional[Path] = None

    if args.path:
        target_path = Path(args.path).resolve()
    else:
        # Prompt folder selector dialog
        target_path = prompt_folder_dialog()


    if not target_path or not target_path.exists():
        print("Error: Target project directory does not exist or was not selected.")
        return 1

    print(f"Starting audit scan for: {target_path}")

    # Load configuration
    if args.config:
        config = load_config_from_file(args.config, target_path)
    else:
        from secret_scanner.config import default_config
        config = default_config(target_path)

    # Apply CLI flag overrides
    if args.no_git:
        config.enable_git = False
    if args.no_entropy:
        config.enable_entropy = False
    if args.entropy_threshold:
        config.entropy_threshold = args.entropy_threshold
    if args.workers:
        config.max_workers = args.workers

    # Run SecretScanner engine
    engine = SecretScannerEngine(config)
    report = engine.run(output_dir=args.output_dir)

    return 0 if report.stats.critical_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
