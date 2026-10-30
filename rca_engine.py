"""Compatibility wrapper — delegates to the sentinel package.

Usage: python rca_engine.py manifestations_filtered/sequences/7-6
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from sentinel.pipeline import cli  # noqa: E402

if __name__ == "__main__":
    cli()
