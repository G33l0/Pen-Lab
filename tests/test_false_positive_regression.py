"""False-positive regression suite.

The core promise of Pen-Lab: an interesting-looking response must NEVER become
a confirmed/validated finding without corroborated evidence. Each case below
feeds a benign-but-tricky response and asserts the verdict is non-actionable
(not VALIDATED, not CONFIRMED). Positive counterparts live in test_validation.
"""
import html

import pytest

from pentest_workstation.app.core.enums import FindingStatus
from pentest_workstation.app.validation import (
    DetectionContext, HttpExchange, ValidationEngine,
)

E = ValidationEngine()
MARKER = "penlab7z<script>x</script>"


def _actionable(result):
    return result.status.is_actionable


# ---- XSS false positives ---------------------------------------------
def test_xss_encoded_reflection_is_not_actionable():
    body = f"<div>{html.escape(MARKER)}</div>"
    r = E.evaluate("reflected_xss", DetectionContext(payload=MARKER, marker=MARKER,
                   test=HttpExchange(status=200, body=body,
                                     response_headers={"Content-Type": "text/html"})))
    assert r.status == FindingStatus.FALSE_POSITIVE
    assert not _actionable(r)


def test_xss_not_reflected_is_not_actionable():
    r = E.evaluate("reflected_xss", DetectionContext(payload=MARKER, marker=MARKER,
                   test=HttpExchange(status=200, body="<div>nothing here</div>")))
    assert not _actionable(r)


def test_xss_waf_block_is_not_actionable():
    r = E.evaluate("reflected_xss", DetectionContext(payload=MARKER, marker=MARKER,
                   test=HttpExchange(status=403,
                                     body="Attention Required! Cloudflare blocked your request")))
    assert not _actionable(r)


def test_xss_runtime_false_is_false_positive():
    body = f"<div>{MARKER}</div>"
    r = E.evaluate("reflected_xss", DetectionContext(payload=MARKER, marker=MARKER,
                   test=HttpExchange(status=200, body=body,
                                     response_headers={"Content-Type": "text/html"}),
                   runtime_executed=False))
    assert r.status == FindingStatus.FALSE_POSITIVE


# ---- SQLi false positives --------------------------------------------
def test_sqli_generic_500_is_not_actionable():
    base = HttpExchange(status=200, body="Products: apple banana cherry")
    r = E.evaluate("differential_sqli", DetectionContext(
        payload="1'", baseline=base,
        test=HttpExchange(status=500, body="Internal Server Error")))
    assert not _actionable(r)


def test_sqli_rate_limit_is_not_actionable():
    base = HttpExchange(status=200, body="Products: apple banana cherry")
    r = E.evaluate("differential_sqli", DetectionContext(
        payload="1'", baseline=base,
        test=HttpExchange(status=429, body="Too Many Requests - rate limit exceeded")))
    assert not _actionable(r)


def test_sqli_waf_block_is_not_actionable():
    base = HttpExchange(status=200, body="Products: apple banana cherry")
    r = E.evaluate("differential_sqli", DetectionContext(
        payload="1'", baseline=base,
        test=HttpExchange(status=403, body="Request blocked by mod_security web application firewall")))
    assert not _actionable(r)


def test_sqli_dynamic_content_is_not_actionable():
    # Baseline and its repeat already differ wildly -> too noisy to conclude.
    base = HttpExchange(status=200, body="Session 111 rows 2 aaa bbb ccc ddd")
    base2 = HttpExchange(status=200, body="Totally 999 different zzz yyy xxx www vvv uuu")
    test = HttpExchange(status=200, body="Another 555 variant qqq rrr sss ttt")
    r = E.evaluate("differential_sqli", DetectionContext(
        payload="1'", baseline=base, test=test, extra={"baseline_repeat": base2}))
    assert not _actionable(r)


def test_sqli_length_change_only_is_not_actionable():
    base = HttpExchange(status=200, body="Products: apple banana cherry date elderberry fig")
    test = HttpExchange(status=200, body="Products: apple banana cherry date elderberry fig grape kiwi")
    r = E.evaluate("differential_sqli", DetectionContext(payload="1'", baseline=base, test=test))
    assert not _actionable(r)


def test_sqli_custom_error_page_without_db_signature():
    base = HttpExchange(status=200, body="Products: apple banana cherry")
    test = HttpExchange(status=200, body="<html>Oops, something went wrong. Please try again.</html>")
    r = E.evaluate("differential_sqli", DetectionContext(payload="1'", baseline=base, test=test))
    assert not _actionable(r)


# ---- open redirect false positives -----------------------------------
def test_open_redirect_same_origin_is_not_actionable():
    r = E.evaluate("open_redirect", DetectionContext(
        payload="/account",
        test=HttpExchange(status=302, url="https://app.test/r",
                          response_headers={"Location": "https://app.test/account"},
                          final_url="https://app.test/account"),
        params={"controlled_host": "evil.example", "origin": "https://app.test/"}))
    assert not _actionable(r)


def test_open_redirect_login_redirect_is_not_actionable():
    r = E.evaluate("open_redirect", DetectionContext(
        payload="x",
        test=HttpExchange(status=302, url="https://app.test/private",
                          response_headers={"Location": "/login?next=/private"},
                          final_url="https://app.test/login"),
        params={"controlled_host": "evil.example", "origin": "https://app.test/"}))
    assert not _actionable(r)


@pytest.mark.parametrize("status,body", [
    (200, "normal page"),
    (500, "Internal Server Error"),
    (429, "rate limit exceeded, too many requests"),
    (403, "Cloudflare attention required blocked"),
    (302, "redirected"),
])
def test_no_detector_confirms_on_status_alone(status, body):
    """Sweep: none of the detectors may confirm from a bare status/body."""
    base = HttpExchange(status=200, body="baseline content apple banana")
    ex = HttpExchange(status=status, body=body)
    for name in ("reflected_xss", "differential_sqli", "open_redirect"):
        r = E.evaluate(name, DetectionContext(payload="p", marker="p", baseline=base, test=ex))
        assert not r.status.is_actionable, f"{name} wrongly actionable on {status}"
