#!/usr/bin/env bash
# Build a Linux executable (dist/pen-lab/). For an AppImage, wrap dist/pen-lab
# with appimagetool separately.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m pip install -e '.[build]'
python3 scripts/build.py
