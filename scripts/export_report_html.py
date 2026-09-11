"""Export an existing VulnAgent JSON report to a self-contained HTML file."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from vulnagent.report.html import write_report_html


def _report_content(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("input JSON must be an object")
    if isinstance(value.get("report"), dict):
        return dict(value["report"])
    if isinstance(value.get("content"), dict):
        return dict(value["content"])
    if isinstance(value.get("task"), dict) and isinstance(value.get("summary"), dict):
        return dict(value)
    raise ValueError("input JSON does not contain a structured VulnAgent report")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--title", default="VulnAgent 漏洞分析报告")
    args = parser.parse_args()
    value = json.loads(args.input.read_text(encoding="utf-8"))
    destination = write_report_html(
        _report_content(value),
        args.output,
        title=args.title,
    )
    print(f"HTML report written: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
