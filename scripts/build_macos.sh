#!/usr/bin/env bash
# Build a macOS app bundle (dist/Pen-Lab.app). Runs on Intel or Apple Silicon;
# the artifact matches the architecture of the Python you build with.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m pip install -e '.[build]'
python3 scripts/build.py
