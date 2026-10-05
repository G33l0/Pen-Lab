# Pen-Lab

A cross-platform **penetration-testing knowledge & operations workstation** built
with Python and PyQt6. Pen-Lab is not a static cheat sheet: it is a structured,
searchable knowledge model wired to a **scope-guarded execution engine** and an
**evidence-based validation engine** designed to resist false positives.

It runs on **Windows, macOS and Linux**. The GUI is PyQt6 only (no Tkinter), and
OS-specific behavior lives behind clean platform adapters.

---

## What it does

- **Knowledge base** — techniques/vulnerabilities as structured records
  (severity, CWE, OWASP, detection/validation methodology, false-positive
  indicators, remediation, references) across Recon, Network, Web, API, Cloud,
  Identity, Mobile, Container, OSINT and Vulnerability Research.
- **Guided walkthroughs** — step-by-step workflows with per-step progress.
- **Tool directory & local inventory** — 34 tools with official links; a scanner
  that validates which are actually installed by running their version command
  (a folder is never treated as proof of installation).
- **Payload library** — structured payloads with context, expected behavior and
  expected evidence; reference/lab/active material is separated; copy / edit /
  encode / decode / explain / save.
- **Validation & evidence** — a differential engine and per-technique detectors
  that only reach VALIDATED/CONFIRMED on corroborated evidence, with a full
  evidence model (request/response/diff/signals/timeline).
- **Workspaces** — engagements, authorized targets with explicit scope, findings
  and exportable reports (HTML / Markdown / PDF).
- **Execution engine** — asynchronous command/HTTP/network execution that never
  runs active tests outside an authorized, in-scope target.
- **Plugins** — a manifest-based plugin system with stable module interfaces so
  new capabilities (recon, network, OSINT, reporting, detectors, UI pages) plug
  in without touching the core.
- **CVE/CWE research, labs, cheatsheets, global search** and three professional
  themes (dark / red team / satellite).

---

## Quick start (from source)

```bash
# 1. Python 3.10+ required
python3 -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate

# 2. Install (GUI extra pulls in PyQt6)
pip install -e ".[gui]"

# 3. Run
python -m pentest_workstation.app.main
#   or, after install:  pen-lab
```

On first run the bundled knowledge base is seeded into a local SQLite database
in your platform's data directory.

Headless initialization check (no GUI — useful for CI / packaging):

```bash
python -m pentest_workstation.app.main --check
```

> **Linux note:** PyQt6 needs system graphics libraries. On Debian/Ubuntu:
> `sudo apt install libegl1 libgl1 libglib2.0-0 libxkbcommon0 libfontconfig1`.

---

## Dependencies

| Group | Install | Contents |
| --- | --- | --- |
| runtime (headless) | `pip install -e .` | SQLAlchemy, PyYAML, requests |
| GUI | `pip install -e ".[gui]"` | + PyQt6 |
| dev/test | `pip install -e ".[dev]"` | + pytest, pytest-cov |
| build | `pip install -e ".[build]"` | + PyInstaller |

`reportlab` is optional; without it, PDF export writes a print-ready HTML file
and tells you to use "Print to PDF" (it never fakes a PDF).

---

## Tests

```bash
QT_QPA_PLATFORM=offscreen pytest            # full suite (UI smoke runs headless)
pytest tests/test_false_positive_regression.py   # the false-positive suite
```

The suite covers unit, database/migrations, parsers, tool detection, platform
and scope, the differential and validation engines, a dedicated false-positive
regression suite, execution against a **local intentionally-vulnerable mock
target** (never the live internet), reporting, import, plugins, the workspace
bridge, and a headless UI smoke test.

---

## Build (Windows / macOS / Linux)

```bash
pip install -e ".[build]"
python scripts/build.py          # or scripts/build_linux.sh | build_macos.sh | build_windows.ps1
```

Artifacts land in `dist/` (`dist/pen-lab/` on Windows/Linux, `dist/Pen-Lab.app`
on macOS). See `docs/build.md` for architecture notes (Intel/ARM) and AppImage.

---

## Project layout

```
pentest_workstation/
  app/
    config/         platform paths + settings
    core/           enums, logging (secret redaction), event bus
    database/       SQLAlchemy engine, migrations, YAML seed loader
    models/         ORM models (knowledge, tools, payloads, workflows, workspace…)
    services/       application services + AppContext composition root
    execution/      scope guard + command/HTTP/network/browser executors + engine
    validation/     differential analyzer, detectors, evidence, validation engine
    tools/          tool registry + adapters (nmap/ffuf/nuclei/httpx/sqlmap)
    platform_adapters/  Windows/macOS/Linux tool detectors
    reporting/      HTML/Markdown/PDF report generators
    plugins/        plugin API (module interfaces) + manager
    ui/             PyQt6 main window, pages, widgets, themes
  data/             seed content (techniques, payloads, tools, labs, cves, …)
plugins/            bundled example plugin (Security Headers Analyzer)
tests/              pytest suite + local mock target fixture
scripts/  build/    build drivers and PyInstaller spec
docs/               architecture, schema, resource format, validation, plugins
```

---

## Documentation

- `docs/architecture.md` — layered architecture and data flow
- `docs/schema.md` — database schema
- `docs/resource_format.md` — YAML/JSON/CSV/Markdown import format
- `docs/validation.md` — the validation / false-positive architecture
- `docs/plugins.md` — plugin development guide
- `docs/build.md` — cross-platform build & packaging
- `docs/limitations.md` — known platform-specific limitations
- `docs/modules.md` — list of implemented modules

---

## Responsible use

Pen-Lab is for **authorized** security testing, education and research. Active
testing requires selecting an authorized, in-scope target; the execution engine
refuses active operations otherwise. Use only against systems you own or have
explicit written permission to test. Tool and resource links point to official
sources; no binaries are bundled.

## License

MIT — see `LICENSE`. Seed content cites authoritative sources (OWASP, MITRE
CWE, NVD, official vendor/tool documentation); referenced third-party projects
remain under their own licenses.
