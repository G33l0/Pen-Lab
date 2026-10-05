"""UI smoke test: construct the main window headless and cycle every page.

Skips cleanly if PyQt6 or an offscreen platform is unavailable.
"""
import os

import pytest

pytest.importorskip("PyQt6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def qapp():
    from PyQt6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    yield app


@pytest.mark.gui
def test_main_window_constructs_and_cycles(qapp, seeded_context):
    from pentest_workstation.app.plugins.manager import PluginManager
    from pentest_workstation.app.ui.main_window import MainWindow

    pm = PluginManager(seeded_context)
    pm.load_all()
    win = MainWindow(seeded_context, pm)
    win.show()
    assert win.nav.count() >= 15
    for row in range(win.nav.count()):
        win.nav.setCurrentRow(row)
        qapp.processEvents()
    # theme switching works
    for theme in ("dark", "red", "satellite"):
        win.apply_theme(theme)
    qapp.processEvents()


@pytest.mark.gui
def test_search_page_returns_results(qapp, seeded_context):
    from pentest_workstation.app.ui.pages.search import SearchPage
    page = SearchPage(seeded_context)
    page.query.setText("xss")
    page.run_search()
    assert page.table.rowCount() >= 1


@pytest.mark.gui
def test_knowledge_page_lists_web(qapp, seeded_context):
    from pentest_workstation.app.ui.pages.knowledge import KnowledgePage
    page = KnowledgePage(seeded_context, domain="web")
    assert page.list.count() >= 5
