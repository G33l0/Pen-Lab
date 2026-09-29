"""Import service tests for JSON / CSV / Markdown."""
import pytest

from pentest_workstation.app.database.seed import SeedError


def test_import_json_records(context):
    context.importer.import_records("tools", [{"slug": "x", "name": "X"}])
    assert context.tools.get("x") is not None


def test_import_csv(tmp_path, context):
    p = tmp_path / "tools.csv"
    p.write_text("slug,name,category,platforms\nt1,Tool1,web,linux;macos\n")
    n = context.importer.import_file(p, "tools")
    assert n == 1
    t = context.tools.get("t1")
    assert t.platforms == ["linux", "macos"]


def test_import_markdown_cheatsheet(tmp_path, context):
    from pentest_workstation.app.models import Cheatsheet
    p = tmp_path / "My Sheet.md"
    p.write_text("## Recon\n```\nnmap host\nwhois d\n```\n")
    context.importer.import_file(p, "cheatsheets")
    cs = context.session.query(Cheatsheet).first()
    assert cs and len(cs.entries) == 2


def test_import_rejects_invalid(context):
    with pytest.raises(SeedError):
        context.importer.import_records("tools", [{"slug": "x", "name": "X", "wat": 1}])


def test_import_unsupported_format(tmp_path, context):
    p = tmp_path / "data.xml"
    p.write_text("<x/>")
    with pytest.raises(SeedError):
        context.importer.import_file(p, "tools")
