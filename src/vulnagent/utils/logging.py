"""Logging configuration."""

import logging


def configure_logging(level: str = "INFO") -> None:
    """Configure application logging once using a conventional text format."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

