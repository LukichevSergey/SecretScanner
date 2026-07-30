#!/usr/bin/env python3
"""
SecretScanner Root Entry Point.
Launches the SecretScanner CLI and audit engine.
Usage:
    python scanner.py
    python scanner.py /path/to/project
"""

import sys
from secret_scanner.cli import main

if __name__ == "__main__":
    sys.exit(main())
