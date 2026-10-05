# Architecture

Pen-Lab is layered so the GUI, business logic and external tools stay decoupled:

```
            PyQt6 UI  (app/ui)
                |  (reads services, emits domain actions)
        Application Services  (app/services)   ── AppContext composition root
                |
   Domain logic: validation (app/validation), execution (app/execution)
                |
         Repositories / ORM  (app/models, app/database)
                |
        SQLite  +  External tools via adapters (app/tools/adapters)
```

Key principles, each enforced in code:

- **GUI is separate from logic.** The UI never talks to the ORM through business
  rules; it calls services on an `AppContext`. Commands run through a `QThread`
  worker (`app/ui/qt_worker.py`) wrapping the Qt-free execution engine, so the
  UI never blocks.
- **External tools are behind adapters.** The core depends on a `ToolRegistry`,
  never on a specific binary. Each adapter is a pure *build command* + *parse
  output* pair; running is the execution engine's job.
- **Scanners are independent of the UI; validation is independent of scanners;
  payloads are independent of the UI.** Each is importable and testable alone.
- **One composition root.** `AppContext` wires database, settings, registry,
  validation, execution and all services. It owns a single long-lived session
  for the UI thread; background execution never touches the ORM.

## Data flow for an active test (PREPARE → EXECUTE → VALIDATE)

1. The user selects an **authorized target** (scope stored on the `Target`).
2. A payload/command is turned into a **preview** (`ExecutionEngine.prepare`),
   showing exactly what will run. Nothing executes yet.
3. On **EXECUTE**, the `ScopeGuard` checks the host against the target's scope;
   out-of-scope operations raise `ScopeError`.
4. HTTP/command results become `HttpExchange`/`ExecutionResult` objects.
5. A **detector** reasons over the evidence via the `ValidationEngine` and
   returns a `ValidationResult` (status + confidence + signals).
6. The result is persisted as a `Finding` + `Evidence`; status/confidence come
   straight from the evidence-based verdict, never inflated.

## Extensibility

`PluginManager` discovers manifest-described plugins and hands each a
`PluginContext` to register detectors, tool adapters, UI pages, reports and
imported knowledge. Module interfaces (`ReconModule`, `NetworkScannerModule`,
`DomainIntelligenceModule`, `OSINTModule`, `VulnerabilityModule`, `ReportModule`)
let future security projects plug in behind stable contracts.
