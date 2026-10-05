"""Reporting output tests."""
from pentest_workstation.app.reporting import html_report, markdown_report
from pentest_workstation.app.reporting.pdf_report import export_pdf

ENG = {"name": "Acme", "client": "Acme Corp", "authorization_note": "SOW-123"}
FINDINGS = [{
    "title": "Reflected XSS", "severity": "high", "status": "confirmed", "confidence": "certain",
    "endpoint": "/search", "parameter": "q", "cwe": "CWE-79", "cve": "", "cvss_score": 0,
    "description": "Reflected input", "impact": "", "reproduction": "", "validation": "runtime confirmed",
    "remediation": "encode output", "payload_used": "<script>x</script>", "references": [],
    "evidence": [{"label": "e1", "request": "GET /search", "response": "HTTP 200",
                  "diff": "status_equal: True", "signals": [{"type": "validation", "name": "runtime",
                  "observed": True, "detail": "confirmed"}], "metrics": {}, "timeline": []}],
}, {
    "title": "Low issue", "severity": "low", "status": "validated", "confidence": "high",
    "evidence": [],
}]


def test_markdown_contains_finding_and_evidence():
    md = markdown_report.render_report(ENG, FINDINGS)
    assert "Reflected XSS" in md and "Evidence 1" in md and "Acme" in md
    # sorted by severity: high before low
    assert md.index("Reflected XSS") < md.index("Low issue")


def test_html_is_valid_document():
    html = html_report.render_report(ENG, FINDINGS)
    assert html.startswith("<!doctype html>") and "Reflected XSS" in html


def test_pdf_fallback_is_honest(tmp_path):
    result = export_pdf(ENG, FINDINGS, tmp_path / "r.pdf")
    # reportlab likely absent in CI -> must return an HTML fallback, not fake a PDF
    assert result.path.endswith((".pdf", ".print.html"))
    if not result.native_pdf:
        assert "reportlab" in result.note.lower()
        assert (tmp_path / "r.print.html").exists()
