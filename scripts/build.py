#!/usr/bin/env python3
"""Cross-platform build driver for Pen-Lab.

Detects the current OS and runs PyInstaller with the shared spec, then reports
where the artifact landed. Requires the 'build' extra (pip install -e .[build]).

    python scripts/build.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "build" / "pen-lab.spec"


def main() -> int:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("PyInstaller is not installed. Run: pip install -e .[build]", file=sys.stderr)
        return 2

    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", str(SPEC),
           "--distpath", str(ROOT / "dist"), "--workpath", str(ROOT / "build" / "_work")]
    print("Running:", " ".join(cmd))
    rc = subprocess.call(cmd, cwd=str(ROOT))
    if rc == 0:
        target = ROOT / "dist" / "pen-lab"
        if sys.platform == "darwin" and (ROOT / "dist" / "Pen-Lab.app").exists():
            target = ROOT / "dist" / "Pen-Lab.app"
        print(f"\nBuild complete: {target}")
        print("Platform:", sys.platform)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
