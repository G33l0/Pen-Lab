"""Database schema, migrations and seed loader tests."""
import pytest
from sqlalchemy import inspect

from pentest_workstation.app import models as m
from pentest_workstation.app.database.base import Database
from pentest_workstation.app.database.migrations import MigrationRunner
from pentest_workstation.app.database.seed import SeedError, SeedLoader


def test_create_all_registers_expected_tables(db):
    tables = set(inspect(db.engine).get_table_names())
    for t in ["techniques", "tools", "payloads", "workflows", "findings", "evidence",
              "cves", "cwes", "engagements", "targets", "plugins"]:
        assert t in tables


def test_migration_runner_applies_and_is_idempotent():
    database = Database.in_memory()
    runner = MigrationRunner(database.engine)
    applied = runner.upgrade()
    assert "0001" in applied
    assert runner.pending() == []
    assert runner.upgrade() == []  # nothing left to apply


def test_seed_upsert_is_idempotent(db):
    s = db.session()
    loader = SeedLoader(s)
    rec = [{"slug": "t1", "name": "Tech One", "severity": "high"}]
    loader.upsert_records("techniques", rec)
    loader.upsert_records("techniques", rec)
    s.commit()
    assert s.query(m.Technique).count() == 1


def test_seed_rejects_unknown_field(db):
    loader = SeedLoader(db.session())
    with pytest.raises(SeedError):
        loader.upsert_records("techniques", [{"slug": "x", "name": "n", "bogus": 1}])


def test_seed_rejects_missing_required(db):
    loader = SeedLoader(db.session())
    with pytest.raises(SeedError):
        loader.upsert_records("techniques", [{"slug": "x"}])


def test_seed_cross_reference_resolution(db):
    s = db.session()
    loader = SeedLoader(s)
    loader.upsert_records("tools", [{"slug": "nmap", "name": "Nmap"}])
    loader.upsert_records("techniques", [{"slug": "t", "name": "T", "tools": ["nmap"]}])
    loader.resolve_references("techniques", [{"slug": "t", "tools": ["nmap"]}])
    s.commit()
    tech = s.query(m.Technique).filter_by(slug="t").one()
    assert [x.slug for x in tech.tools] == ["nmap"]


def test_bundled_seed_loads(seeded_context):
    assert seeded_context.knowledge.count() >= 25
    assert seeded_context.tools.count() >= 30
    assert seeded_context.payloads.count() >= 10
