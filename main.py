#!/usr/bin/env python3
"""
dLNk dLNk Framework - Main Entry Point
"""

import sys
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from cli.main import cli

if __name__ == "__main__":
    cli()

