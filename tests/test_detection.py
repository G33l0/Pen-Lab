"""Tool detection tests with injected which/runner (no real binaries)."""
import os

from pentest_workstation.app.core.enums import OSFamily, ToolStatus
from pentest_workstation.app.platform_adapters import get_detector
from pentest_workstation.app.platform_adapters.base import ToolProbe
from pentest_workstation.app.platform_adapters.linux import LinuxToolDetector
from pentest_workstation.app.platform_adapters.windows import WindowsToolDetector


def _probe(**kw):
    kw.setdefault("slug", "t")
    kw.setdefault("executable", "tool")
    kw.setdefault("version_args", ["--version"])
    kw.setdefault("version_regex", r"(\d+\.\d+)")
    return ToolProbe(**kw)


def test_installed_with_version():
    det = LinuxToolDetector(which=lambda n: "/usr/bin/tool" if n == "tool" else None,
                            runner=lambda cmd, t: (0, "tool version 7.94", ""))
    det.is_executable = lambda p: p == "/usr/bin/tool"
    r = det.detect(_probe())
    assert r.status == ToolStatus.INSTALLED and r.version == "7.94"


def test_not_found():
    det = LinuxToolDetector(which=lambda n: None, runner=lambda c, t: (0, "", ""))
    r = det.detect(_probe())
    assert r.status == ToolStatus.NOT_FOUND and not r.installed


def test_found_but_no_version():
    det = LinuxToolDetector(which=lambda n: "/usr/bin/tool" if n == "tool" else None,
                            runner=lambda c, t: (1, "", "unknown flag"))
    det.is_executable = lambda p: True
    r = det.detect(_probe())
    assert r.status == ToolStatus.FOUND_NO_VERSION and r.installed


def test_directory_is_not_installed(tmp_path):
    # A directory with the tool's name must not count as installed.
    (tmp_path / "tool").mkdir()
    det = LinuxToolDetector(which=lambda n: None)
    r = det.detect(_probe(common_locations={"linux": [str(tmp_path / "tool")]}))
    assert r.status == ToolStatus.NOT_FOUND


def test_windows_pathext_expansion():
    os.environ["PATHEXT"] = ".COM;.EXE;.BAT"
    seen = {}
    def which(name):
        seen[name] = True
        return "C:/tools/tool.exe" if name.lower() == "tool.exe" else None
    det = WindowsToolDetector(which=which, runner=lambda c, t: (0, "tool version 1.2", ""))
    det.is_executable = lambda p: p == "C:/tools/tool.exe"
    r = det.detect(_probe())
    assert r.status == ToolStatus.INSTALLED
    assert any(n.lower() == "tool.exe" for n in seen)


def test_real_python_detection():
    det = get_detector()
    r = det.detect(ToolProbe(slug="python", executable="python3",
                             version_args=["--version"], version_regex=r"(\d+\.\d+\.\d+)"))
    # python3 exists in the test environment
    assert r.installed and r.version
