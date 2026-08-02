#!/usr/bin/env python3
"""
Executable wrapper script for SeqSig CLI.
"""

import os
import sys

# Ensure src directory is in sys.path when executed directly
src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from seqsig.cli import main

if __name__ == "__main__":
    main()
