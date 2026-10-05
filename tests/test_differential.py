"""Differential analysis engine tests."""
from pentest_workstation.app.validation.differential import (
    DifferentialAnalyzer, normalize_body, text_similarity,
)
from pentest_workstation.app.validation.models import HttpExchange


def test_normalization_masks_volatile_tokens():
    a = "user 12345 at 2024-01-01 10:00:00 token abcdef1234567890abcdef"
    b = "user 98765 at 2024-06-02 11:22:33 token 0000ffff0000ffff00001111"
    assert normalize_body(a) == normalize_body(b)


def test_similarity_ignores_dynamic_noise():
    a = HttpExchange(body="Welcome user 12345 session 99999")
    b = HttpExchange(body="Welcome user 67890 session 11111")
    assert text_similarity(a.body, b.body) > 0.95


def test_similarity_detects_real_change():
    a = HttpExchange(body="Products: apple banana cherry")
    b = HttpExchange(body="No products found")
    assert text_similarity(a.body, b.body) < 0.6


def test_compare_reports_status_and_ct():
    d = DifferentialAnalyzer()
    a = HttpExchange(status=200, body="x", response_headers={"Content-Type": "text/html"})
    b = HttpExchange(status=500, body="err", response_headers={"Content-Type": "text/plain"})
    rep = d.compare(a, b)
    assert not rep.status_equal and not rep.content_type_equal


def test_noise_ratio_zero_for_identical():
    d = DifferentialAnalyzer()
    a = HttpExchange(body="stable content here")
    assert d.noise_ratio(a, a) == 0.0


def test_cookie_diff():
    d = DifferentialAnalyzer()
    a = HttpExchange(response_headers={"Set-Cookie": "a=1"})
    b = HttpExchange(response_headers={"Set-Cookie": "a=1, b=2"})
    rep = d.compare(a, b)
    assert "b" in rep.cookies_added
