# Implemented modules

| Area | Module(s) | Status |
| --- | --- | --- |
| Config & paths | `app/config` | platform-aware dirs + JSON settings |
| Logging | `app/core/logging_setup` | rotating file + console, secret redaction |
| Database | `app/database` | SQLAlchemy 2.0, migration runner, YAML/JSON/CSV/MD seed |
| Domain models | `app/models` | 30 tables incl. knowledge, tools, payloads, workspace |
| Platform detection | `app/platform_adapters` | Windows/macOS/Linux detectors |
| Tool registry/adapters | `app/tools` | nmap, ffuf, nuclei, httpx, sqlmap |
| Differential engine | `app/validation/differential` | multi-dimension, noise-aware |
| Validation detectors | `app/validation/detectors` | reflected XSS, differential SQLi, open redirect |
| Validation engine | `app/validation/engine` | verdict + evidence builder |
| Execution | `app/execution` | scope guard, command/HTTP/network/browser, engine |
| Services | `app/services` | knowledge, payloads, tools, workflows, workspace, search, import, report |
| Reporting | `app/reporting` | HTML, Markdown, PDF (reportlab or HTML fallback) |
| Plugins | `app/plugins` | manager, API, module interfaces |
| UI | `app/ui` | 20+ pages, 3 themes, console, evidence viewer |
| Example plugin | `plugins/example_headers_plugin` | Security Headers detector + knowledge |

## Validation detectors shipped

- `reflected_xss` — reflection + executable context + runtime confirmation
- `differential_sqli` — boolean / error / time differentials, noise-aware
- `open_redirect` — deterministic controlled-host redirect
- `security_headers` — (plugin) missing HTTP security headers
