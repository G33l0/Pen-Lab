"""Plugin system tests using the bundled example plugin."""
from pathlib import Path

import pytest

from pentest_workstation.app.plugins.manager import PluginError, PluginManager, version_ge

PLUGINS_DIR = Path(__file__).resolve().parents[1] / "plugins"


def test_version_compare():
    assert version_ge("1.0.0", "0.9.0")
    assert version_ge("0.1.0", "0.1.0")
    assert not version_ge("0.1.0", "0.2.0")


def test_discovery_finds_example(context):
    pm = PluginManager(context, search_dirs=[PLUGINS_DIR])
    disc = pm.discover()
    assert any(d.id == "security-headers" for d in disc)


def test_load_registers_detector_and_imports(context):
    pm = PluginManager(context, search_dirs=[PLUGINS_DIR])
    pm.load_all()
    assert "security-headers" in pm.loaded
    assert "security_headers" in context.validation.names()
    assert context.knowledge.get("missing-security-headers") is not None


def test_min_version_guard(context, tmp_path):
    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / "manifest.json").write_text(
        '{"id":"bad","name":"Bad","version":"1.0","entry_point":"plugin.py:X",'
        '"minimum_app_version":"99.0.0"}')
    (tmp_path / "bad" / "plugin.py").write_text("class X: pass")
    pm = PluginManager(context, search_dirs=[tmp_path])
    # discovery validates and skips the incompatible plugin
    assert pm.discover() == []
