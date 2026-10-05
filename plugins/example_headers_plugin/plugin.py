"""Example plugin: HTTP security-headers analyzer.

Demonstrates the plugin API by registering a real, deterministic detector and
seeding a knowledge-base technique. The detector reports which recommended
security headers are absent. Because header presence is deterministic, a clear
absence is VALIDATED (high confidence); it never fabricates exploitation.
"""
from __future__ import annotations

from pentest_workstation.app.core.enums import Confidence, FindingStatus, SignalType
from pentest_workstation.app.plugins.api import Plugin, PluginContext, VulnerabilityModule
from pentest_workstation.app.validation.detectors.base import Detector
from pentest_workstation.app.validation.models import (
    DetectionContext, Signal, ValidationResult,
)

RECOMMENDED = {
    "content-security-policy": "Mitigates XSS and data injection by restricting sources.",
    "x-content-type-options": "Prevents MIME sniffing (should be 'nosniff').",
    "x-frame-options": "Mitigates clickjacking (or use CSP frame-ancestors).",
    "strict-transport-security": "Enforces HTTPS (HSTS).",
    "referrer-policy": "Controls Referer header leakage.",
}


class SecurityHeadersDetector(Detector):
    name = "security_headers"
    technique = "Missing HTTP security headers"
    required_evidence = ("a response whose headers were inspected",)

    def evaluate(self, ctx: DetectionContext) -> ValidationResult:
        res = ValidationResult(FindingStatus.NOT_TESTED, Confidence.NONE, self.name)
        ex = ctx.test or ctx.baseline
        if ex is None:
            res.rationale = "No response captured."
            return res
        present = {k.lower() for k in (ex.response_headers or {})}
        missing = [h for h in RECOMMENDED if h not in present]
        for h in RECOMMENDED:
            observed = h not in present
            res.add_signal(Signal(SignalType.DETECTION, f"missing:{h}", observed,
                                  RECOMMENDED[h] if observed else "present"))
        res.metrics["missing_headers"] = missing
        if missing:
            res.status = FindingStatus.VALIDATED
            res.confidence = Confidence.HIGH
            res.rationale = "Missing recommended security headers: " + ", ".join(missing)
        else:
            res.status = FindingStatus.INCONCLUSIVE
            res.confidence = Confidence.HIGH
            res.rationale = "All recommended security headers are present."
        return res


class HeadersModule(VulnerabilityModule):
    def detectors(self):
        return [SecurityHeadersDetector()]


class SecurityHeadersPlugin(Plugin):
    id = "security-headers"
    name = "Security Headers Analyzer"
    version = "1.0.0"

    def setup(self, ctx: PluginContext) -> None:
        for det in HeadersModule().detectors():
            ctx.register_detector(det)
        ctx.import_records("categories", [{
            "slug": "web-security-headers", "domain": "web", "name": "Security Headers",
            "description": "Missing or misconfigured HTTP response security headers.",
        }])
        ctx.import_records("techniques", [{
            "slug": "missing-security-headers",
            "name": "Missing HTTP Security Headers",
            "category_slug": "web-security-headers",
            "severity": "low",
            "summary": "Recommended security headers are absent from responses.",
            "detection_methodology": "Inspect response headers for CSP, HSTS, X-Content-Type-"
                                     "Options, X-Frame-Options and Referrer-Policy.",
            "validation_methodology": "Header presence is deterministic; confirm across "
                                      "representative endpoints.",
            "remediation": "Configure the recommended headers at the web server or app layer.",
            "tags": ["headers", "hardening", "web"],
        }])
