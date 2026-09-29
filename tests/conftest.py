"""Shared pytest fixtures."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Ensure the repository root is importable so 'pentest_workstation' resolves the
# same way plugins and the packaged app import it.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from pentest_workstation.app.config.settings import Settings  # noqa: E402
from pentest_workstation.app.database.base import Database  # noqa: E402
from pentest_workstation.app.services.context import AppContext  # noqa: E402


@pytest.fixture
def db():
    database = Database.in_memory()
    database.create_all()
    yield database


@pytest.fixture
def context():
    database = Database.in_memory()
    ctx = AppContext(settings=Settings(), database=database)
    yield ctx
    ctx.close()


@pytest.fixture
def seeded_context(context):
    context.importer.seed_bundled(context.data_dir)
    return context


@pytest.fixture
def mock_target():
    from tests.fixtures.mock_target import MockTarget
    with MockTarget() as target:
        yield target
