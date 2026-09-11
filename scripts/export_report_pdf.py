"""Export an existing VulnAgent JSON report to a printable PDF file."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from vulnagent.report.pdf import write_report_pdf

if __package__:
    from .export_report_html import _report_content
else:
    from export_report_html import _report_content


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--title", default="VulnAgent 漏洞分析报告")
    args = parser.parse_args()
    value = json.loads(args.input.read_text(encoding="utf-8"))
    destination = write_report_pdf(
        _report_content(value),
        args.output,
        title=args.title,
    )
    print(f"PDF report written: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
