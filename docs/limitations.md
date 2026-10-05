# Known platform-specific limitations

- **External tools are optional.** Pen-Lab functions fully (knowledge base,
  payloads, workflows, validation, reporting) even when no scanners are
  installed. Not every tool exists on every OS (e.g. Responder is Linux-only;
  WhatWeb/testssl.sh are not packaged for Windows). The tool directory records
  per-tool platform support and the inventory reports what is actually present.
- **Runtime XSS confirmation needs a browser.** The `BrowserExecutor` uses
  Playwright if installed; without it, reflected-XSS verdicts are capped at
  SUSPECTED rather than CONFIRMED (never fabricated). Install Playwright and a
  browser to enable runtime confirmation.
- **PDF export needs reportlab.** Without it, export writes a print-ready HTML
  file and instructs you to use the browser's "Print to PDF".
- **Linux GUI needs system Qt libraries** (libEGL/libGL/libxkbcommon/…). These
  are OS packages, not pip wheels.
- **Windows ARM64 / macOS arch** builds require a matching PyQt6 wheel and a
  matching-arch Python; build on the target architecture.
- **Tool detection runs version commands.** A tool that refuses to report a
  version is reported as `found_no_version` (present but unverified), never as a
  confirmed version.
- **Privileged operations are never performed silently.** Pen-Lab does not
  modify firewalls/proxies, install software, or store credentials in plaintext.
