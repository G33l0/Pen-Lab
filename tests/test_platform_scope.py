"""Platform helpers and scope-guard tests."""
import pytest

from pentest_workstation.app.execution.scope import ScopeError, ScopeGuard, extract_host


class _Target:
    def __init__(self, authorized=True, include=None, exclude=None, base_url="https://app.test"):
        self.name = "t"
        self.authorized = authorized
        self.base_url = base_url
        self.host = "app.test"
        self.scope_include = include if include is not None else ["app.test"]
        self.scope_exclude = exclude or []


def test_extract_host():
    assert extract_host("https://app.test/x?y=1") == "app.test"
    assert extract_host("app.test:8443") == "app.test"


def test_in_scope_exact():
    assert ScopeGuard().evaluate(_Target(), "https://app.test/a").allowed


def test_glob_subdomain():
    g = ScopeGuard()
    assert g.evaluate(_Target(include=["*.app.test"]), "https://api.app.test/").allowed


def test_cidr_scope():
    g = ScopeGuard()
    t = _Target(include=["10.0.0.0/24"])
    assert g.evaluate(t, "10.0.0.5").allowed
    assert not g.evaluate(t, "10.0.1.5").allowed


def test_exclude_takes_precedence():
    g = ScopeGuard()
    t = _Target(include=["*.app.test"], exclude=["admin.app.test"])
    assert not g.evaluate(t, "https://admin.app.test/").allowed


def test_unauthorized_target_blocked():
    assert not ScopeGuard().evaluate(_Target(authorized=False), "https://app.test/").allowed


def test_no_target_blocked():
    assert not ScopeGuard().evaluate(None, "https://app.test/").allowed


def test_require_raises():
    with pytest.raises(ScopeError):
        ScopeGuard().require(_Target(), "https://evil.com/")
