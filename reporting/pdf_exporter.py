"""
reporting/pdf_exporter.py
PDF export for BlueSentinel v2.0 reports using WeasyPrint.
Generates professional PDF with header/footer from HTML report.
"""
import logging
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger(__name__)
REPORTS_DIR = Path(__file__).parent.parent / "reports"


class PDFExporter:
    """Converts HTML reports to PDF using WeasyPrint."""

    def export(self, scan_result: Any, html_path: Optional[str] = None) -> Optional[str]:
        """Export scan result to PDF. Returns output path or None on failure."""
        try:
            from weasyprint import HTML, CSS
        except ImportError:
            log.error("weasyprint not installed. PDF export unavailable. Run: pip install weasyprint")
            return None

        REPORTS_DIR.mkdir(exist_ok=True)

        if html_path is None:
            from reporting.html_report_generator import generate_html_report
            html_path = generate_html_report(scan_result)

        html_file = Path(html_path)
        if not html_file.exists():
            log.error(f"HTML file not found: {html_path}")
            return None

        pdf_path = str(html_file.with_suffix(".pdf"))

        # Additional CSS for print formatting
        extra_css = CSS(string="""
            @page {
                margin: 20mm 15mm;
                @top-center {
                    content: "BlueSentinel v2.0 | CONFIDENTIAL";
                    font-size: 9pt;
                    color: #ff3b5c;
                    font-family: monospace;
                }
                @bottom-left {
                    content: string(hostname);
                    font-size: 8pt;
                    color: #667788;
                    font-family: monospace;
                }
                @bottom-right {
                    content: "Page " counter(page) " of " counter(pages);
                    font-size: 8pt;
                    color: #667788;
                    font-family: monospace;
                }
            }
            body {
                background: white !important;
                color: black !important;
            }
        """)

        try:
            HTML(filename=str(html_file)).write_pdf(
                pdf_path,
                stylesheets=[extra_css],
                presentational_hints=True,
            )
            log.info(f"PDF report generated: {pdf_path}")
            return pdf_path
        except Exception as exc:
            log.error(f"PDF generation failed: {exc}")
            return None

    def export_from_dict(self, data: dict, html_path: Optional[str] = None) -> Optional[str]:
        """Export from a result dict."""
        try:
            from weasyprint import HTML, CSS
        except ImportError:
            log.error("weasyprint not installed")
            return None

        if html_path is None:
            from reporting.html_report_generator import generate_html_report_from_dict
            html_path = generate_html_report_from_dict(data)

        return self.export(None, html_path)
