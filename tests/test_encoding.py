"""Payload encoding/decoding tests."""
import pytest

from pentest_workstation.app.services import encoding


@pytest.mark.parametrize("scheme", ["url", "url_all", "base64", "html", "hex", "unicode"])
def test_encode_decode_roundtrip(scheme):
    text = "a b&c<'\"/=payload"
    enc = encoding.encode(text, scheme)
    dec = encoding.decode(enc, scheme)
    assert dec == text


def test_html_encode_neutralizes_tags():
    assert encoding.encode("<script>", "html") == "&lt;script&gt;"


def test_base64_known_value():
    assert encoding.encode("penlab", "base64") == "cGVubGFi"


def test_explain_returns_text():
    assert "Base64" in encoding.explain("base64")


def test_unknown_scheme_raises():
    with pytest.raises(ValueError):
        encoding.encode("x", "nope")
