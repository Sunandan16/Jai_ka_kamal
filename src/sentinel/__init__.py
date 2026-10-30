"""Sentinel — CAM-LDS Cybersecurity Root Cause Analysis Engine.

Hybrid pipeline: deterministic normalization + correlation rules, with an
optional LLM stage for semantic correlation and threat assessment.

Entry point:  sentinel <scenario-folder>
"""
from .pipeline import cli


def main() -> None:
    cli()


__all__ = ["main"]
