#!/usr/bin/env python3
"""
cli.py - Main Command-Line Interface for Linux Security & Hardening Toolkit.
Provides interactive menu, comprehensive command options, category filtering,
and script execution capabilities.
"""
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from scanner.main import main

if __name__ == "__main__":
    main()
