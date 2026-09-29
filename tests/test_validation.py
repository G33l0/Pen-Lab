"""Positive/expected-verdict tests for the validation detectors."""
import html

from pentest_workstation.app.core.enums import Confidence, FindingStatus
from pentest_workstation.app.validation import (
    DetectionContext, HttpExchange, ValidationEngine,
)

MARKER = "penlab7z<script>window['__PENLAB_XSS__']=true</script>"


def engine():
    return ValidationEngine()


# ---- reflected XSS ---------------------------------------------------
def test_xss_confirmed_only_with_runtime():
    ctx = DetectionContext(payload=MARKER, marker=MARKER,
                           test=HttpExchange(status=200, body=f"<div>{MARKER}</div>",
                                             response_headers={"Content-Type": "text/html"}),
                           runtime_executed=True)
    r = engine().evaluate("reflected_xss", ctx)
    assert r.status == FindingStatus.CONFIRMED and r.confidence == Confidence.CERTAIN


def test_xss_without_runtime_is_suspected_not_confirmed():
    ctx = DetectionContext(payload=MARKER, marker=MARKER,
                           test=HttpExchange(status=200, body=f"<div>{MARKER}</div>",
                                             response_headers={"Content-Type": "text/html"}))
    r = engine().evaluate("reflected_xss", ctx)
    assert r.status == FindingStatus.SUSPECTED
    assert not r.status.is_actionable


# ---- differential SQLi ----------------------------------------------
def test_sqli_validated_with_boolean_differential():
    base = HttpExchange(status=200, body="Products: apple banana cherry date")
    base2 = HttpExchange(status=200, body="Products: apple banana cherry date")
    true_r = HttpExchange(status=200, body="Products: apple banana cherry date")
    false_r = HttpExchange(status=200, body="No products found")
    ctx = DetectionContext(payload="1' AND 1=1-- -", baseline=base, test=true_r,
                           extra={"true": true_r, "false": false_r, "baseline_repeat": base2})
    r = engine().evaluate("differential_sqli", ctx)
    assert r.status == FindingStatus.VALIDATED


def test_sqli_confirmed_with_two_independent_signals():
    base = HttpExchange(status=200, body="Products: apple banana cherry date")
    base2 = HttpExchange(status=200, body="Products: apple banana cherry date")
    true_r = HttpExchange(status=200, body="Products: apple banana cherry date")
    false_r = HttpExchange(status=200, body="No products found")
    err = HttpExchange(status=500, body="You have an error in your SQL syntax near '''")
    ctx = DetectionContext(payload="1'", baseline=base, test=err,
                           extra={"true": true_r, "false": false_r, "baseline_repeat": base2})
    r = engine().evaluate("differential_sqli", ctx)
    assert r.status == FindingStatus.CONFIRMED


# ---- open redirect ---------------------------------------------------
def test_open_redirect_confirmed_deterministic():
    ctx = DetectionContext(
        payload="//evil.example",
        test=HttpExchange(status=302, url="https://app.test/r?u=//evil.example",
                          response_headers={"Location": "https://evil.example/"},
                          final_url="https://evil.example/"),
        params={"controlled_host": "evil.example", "origin": "https://app.test/"})
    r = engine().evaluate("open_redirect", ctx)
    assert r.status == FindingStatus.CONFIRMED


def test_unknown_detector_is_not_tested():
    r = engine().evaluate("does_not_exist", DetectionContext())
    assert r.status == FindingStatus.NOT_TESTED
