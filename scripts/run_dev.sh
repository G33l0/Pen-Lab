#!/usr/bin/env bash
# Run Pen-Lab from source.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m pentest_workstation.app.main "$@"
