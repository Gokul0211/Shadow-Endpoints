#!/usr/bin/env python3
"""
Shadow Endpoints scanner - entry point.

Usage is identical to the original single-file main.py:

    python main.py --target http://localhost:3001 --output results.json

The implementation lives in the shadow_scanner/ package; see README.md for
a map of where everything is.
"""
from shadow_scanner.cli import main

if __name__ == "__main__":
    main()
