"""Logging configuration."""

import logging


class _ContextDefaults(logging.Filter):
    """Supply correlation fields for records emitted by dependencies."""

    def filter(self, record: logging.LogRecord) -> bool:
        for field in ("task_id", "agent", "module", "event"):
            if not hasattr(record, field):
                setattr(record, field, "-")
        return True


def configure_logging(level: str = "INFO") -> None:
    """Configure application logging once using a conventional text format."""
    handler = logging.StreamHandler()
    handler.addFilter(_ContextDefaults())
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s task_id=%(task_id)s agent=%(agent)s module=%(module)s event=%(event)s %(name)s %(message)s"))
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), handlers=[handler], force=True)
