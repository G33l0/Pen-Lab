# Build & packaging

Pen-Lab packages with PyInstaller using one shared spec (`build/pen-lab.spec`)
that bundles the seed data, resources and the bundled plugins.

```bash
pip install -e ".[build]"
python scripts/build.py
```

Per-OS convenience wrappers:

- Linux: `scripts/build_linux.sh` → `dist/pen-lab/` (wrap with `appimagetool`
  for an AppImage).
- macOS: `scripts/build_macos.sh` → `dist/Pen-Lab.app`.
- Windows: `scripts/build_windows.ps1` → `dist\pen-lab\`.

## Architectures

PyInstaller produces an artifact for the architecture of the Python it runs
with. Build on the matching OS/arch for each target:

| Target | How |
| --- | --- |
| Windows x64 | build on Windows x64 |
| Windows ARM64 | build on Windows ARM64 (where a PyQt6 wheel exists) |
| macOS Intel | build with an x86_64 Python |
| macOS Apple Silicon | build with an arm64 Python |
| Linux x86_64 / ARM64 | build on the matching Linux arch |

Cross-compilation is not supported by PyInstaller; use a matching machine or CI
runner per target. The frozen app locates bundled data/plugins via
`sys._MEIPASS` (see `app/config/paths.py`).

## Smoke-testing a build

```bash
./dist/pen-lab/pen-lab --check        # headless init; prints content/plugin counts
```
