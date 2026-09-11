"""Report generation and presentation projections."""

from .html import render_report_html, write_report_html
from .pdf import write_report_pdf

__all__ = ["render_report_html", "write_report_html", "write_report_pdf"]
