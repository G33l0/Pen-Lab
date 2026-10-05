"""Execution engine tests, including against the local mock target."""
import pytest

from pentest_workstation.app.config.settings import Settings
from pentest_workstation.app.core.enums import ExecutionMode
from pentest_workstation.app.execution import (
    CommandExecutor, ExecutionEngine, ExecutionRequest, HTTPExecutor, NetworkExecutor,
    ScopeError,
)
from pentest_workstation.app.validation import DetectionContext


class _Target:
    name = "mock"; authorized = True
    def __init__(self, host):
        self.host = host; self.base_url = f"http://{host}"
        self.scope_include = [host.split(":")[0]]; self.scope_exclude = []


def test_command_executor_runs():
    r = CommandExecutor().run_sync(ExecutionRequest(argv=["python3", "-c", "print('ok')"]))
    assert r.exit_code == 0 and "ok" in r.stdout


def test_command_executor_timeout():
    r = CommandExecutor().run_sync(
        ExecutionRequest(argv=["python3", "-c", "import time; time.sleep(5)"], timeout=0.5))
    assert r.timed_out


def test_execute_blocks_out_of_scope():
    eng = ExecutionEngine()
    req = ExecutionRequest(argv=["echo", "hi"], mode=ExecutionMode.EXECUTE, target_host="evil.com")
    with pytest.raises(ScopeError):
        eng.execute(req, target=_Target("app.test"), async_=False)


def test_prepare_does_not_run():
    eng = ExecutionEngine()
    prev = eng.run_tool("nmap", target=_Target("app.test"), mode=ExecutionMode.PREPARE,
                        target_host="app.test", targets=["app.test"], ports="80")
    assert prev.command.startswith("nmap") and prev.scope_ok


def test_http_executor_against_mock(mock_target):
    ex = HTTPExecutor(Settings())
    host = mock_target.base_url
    r = ex.send("GET", f"{host}/reflect", params={"q": "hello123"})
    assert r.status == 200 and "hello123" in r.body


def test_network_port_check_against_mock(mock_target):
    from urllib.parse import urlparse
    p = urlparse(mock_target.base_url)
    res = NetworkExecutor().check_port(p.hostname, p.port, timeout=2)
    assert res.open


def test_end_to_end_xss_against_mock(mock_target):
    """HTTPExecutor + validation engine against the intentionally-vulnerable /reflect."""
    ex = HTTPExecutor(Settings())
    eng = ExecutionEngine(Settings())
    marker = "penlabXSS<script>window['__PENLAB_XSS__']=true</script>"
    resp = ex.send("GET", f"{mock_target.base_url}/reflect", params={"q": marker})
    ctx = DetectionContext(payload=marker, marker=marker, test=resp)
    # No runtime available here -> must be SUSPECTED, never CONFIRMED.
    r = eng.validate("reflected_xss", ctx)
    assert r.status.value == "suspected"


def test_end_to_end_sqli_against_mock(mock_target):
    ex = HTTPExecutor(Settings())
    eng = ExecutionEngine(Settings())
    base = ex.send("GET", f"{mock_target.base_url}/search", params={"q": "1"})
    base2 = ex.send("GET", f"{mock_target.base_url}/search", params={"q": "1"})
    true_r = ex.send("GET", f"{mock_target.base_url}/search", params={"q": "1' AND 1=1-- -"})
    false_r = ex.send("GET", f"{mock_target.base_url}/search", params={"q": "1' AND 1=2-- -"})
    ctx = DetectionContext(payload="1' AND 1=1", baseline=base, test=true_r,
                           extra={"true": true_r, "false": false_r, "baseline_repeat": base2})
    r = eng.validate("differential_sqli", ctx)
    assert r.status.value in ("validated", "confirmed")


def test_end_to_end_false_positive_dynamic(mock_target):
    """The /dynamic endpoint changes every call; SQLi must NOT be actionable."""
    ex = HTTPExecutor(Settings())
    eng = ExecutionEngine(Settings())
    base = ex.send("GET", f"{mock_target.base_url}/dynamic")
    base2 = ex.send("GET", f"{mock_target.base_url}/dynamic")
    test = ex.send("GET", f"{mock_target.base_url}/dynamic")
    ctx = DetectionContext(payload="1'", baseline=base, test=test, extra={"baseline_repeat": base2})
    r = eng.validate("differential_sqli", ctx)
    assert not r.status.is_actionable
