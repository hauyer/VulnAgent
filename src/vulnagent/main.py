"""Development entry point for the VulnAgent API."""

import uvicorn

from vulnagent.settings import get_settings
from vulnagent.utils.logging import configure_logging


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    uvicorn.run("vulnagent.api.app:app", host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
