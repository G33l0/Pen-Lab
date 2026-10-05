# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for Pen-Lab.

Builds a one-folder application bundling the seed data, resources and the
bundled plugins. Run via: pyinstaller build/pen-lab.spec  (from the repo root),
or use scripts/build.py which selects sensible per-OS options.
"""
import sys
from pathlib import Path

ROOT = Path(SPECPATH).resolve().parent  # repo root (build/ is one level down)

datas = [
    (str(ROOT / "pentest_workstation" / "data"), "data"),
    (str(ROOT / "pentest_workstation" / "app" / "resources"), "resources"),
    (str(ROOT / "plugins"), "plugins"),
]

hiddenimports = [
    "pentest_workstation.app.models",
    "pentest_workstation.app.tools.adapters",
    "pentest_workstation.app.validation.detectors",
    "pentest_workstation.app.ui.pages",
]

block_cipher = None

a = Analysis(
    [str(ROOT / "pentest_workstation" / "__main__.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    # tkinter is never used (PyQt6 only). 'cryptography' is not a Pen-Lab
    # dependency (HTTP uses requests + stdlib ssl); excluding it avoids pulling
    # an unrelated/optional transitive package into the bundle.
    excludes=["tkinter", "cryptography", "OpenSSL"],
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz, a.scripts, [], exclude_binaries=True,
    name="pen-lab",
    debug=False, bootloader_ignore_signals=False, strip=False, upx=False,
    console=False,
)
coll = COLLECT(
    exe, a.binaries, a.zipfiles, a.datas,
    strip=False, upx=False, name="pen-lab",
)

# macOS: also produce a .app bundle
if sys.platform == "darwin":
    app = BUNDLE(coll, name="Pen-Lab.app", icon=None, bundle_identifier="dev.penlab.app")
