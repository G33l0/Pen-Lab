"""Tool adapter command-building and output-parsing tests (no binaries)."""
import pytest

from pentest_workstation.app.tools.registry import ToolRegistry


@pytest.fixture
def registry():
    return ToolRegistry()


def test_nmap_build_and_parse(registry):
    nmap = registry.get("nmap")
    cmd = nmap.build_command(targets=["h"], ports="80,443")
    assert cmd.argv[:3] == ["nmap", "-oX", "-"] and "80,443" in cmd.argv
    xml = ('<nmaprun><host><address addr="1.2.3.4"/><ports>'
           '<port protocol="tcp" portid="80"><state state="open"/>'
           '<service name="http" product="nginx" version="1.25"/></port></ports></host></nmaprun>')
    parsed = nmap.parse(xml)
    assert parsed[0]["port"] == 80 and parsed[0]["service"] == "http"


def test_nmap_parse_handles_garbage(registry):
    assert registry.get("nmap").parse("not xml") == []


def test_ffuf_requires_fuzz_marker(registry):
    with pytest.raises(ValueError):
        registry.get("ffuf").build_command(url="https://h/", wordlist="w")


def test_ffuf_parse(registry):
    out = '{"results":[{"input":{"FUZZ":"admin"},"url":"https://h/admin","status":200,"length":5}]}'
    parsed = registry.get("ffuf").parse(out)
    assert parsed[0]["input"] == "admin" and parsed[0]["status"] == 200


def test_nuclei_parse_jsonl(registry):
    out = '{"template-id":"x","info":{"name":"n","severity":"high"},"matched-at":"http://h"}\n'
    parsed = registry.get("nuclei").parse(out)
    assert parsed[0]["severity"] == "high"


def test_httpx_parse(registry):
    out = '{"url":"http://h","status_code":200,"title":"Home"}'
    parsed = registry.get("httpx").parse(out)
    assert parsed[0]["status_code"] == 200


def test_sqlmap_parse_extracts_verdict(registry):
    out = "parameter 'id' is vulnerable. back-end DBMS: MySQL"
    parsed = registry.get("sqlmap").parse(out)
    assert parsed["tool_reports_injectable"] is True
    assert "id" in parsed["vulnerable_parameters"]
    assert parsed["dbms"] == "MySQL"


def test_sqlmap_parse_negative(registry):
    parsed = registry.get("sqlmap").parse("all tested parameters do not appear to be injectable")
    assert parsed["tool_reports_injectable"] is False
