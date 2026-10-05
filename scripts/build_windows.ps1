# Build a Windows executable (dist\pen-lab\). Run from the repo root in PowerShell.
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)
python -m pip install -e ".[build]"
python scripts/build.py
