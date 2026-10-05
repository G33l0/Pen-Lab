# Plugin development

Plugins extend Pen-Lab without modifying the core. A plugin is a directory with
a `manifest.json` and a `Plugin` subclass.

## Layout

```
plugins/
  my_plugin/
    manifest.json
    plugin.py
```

## manifest.json

```json
{
  "id": "my-plugin",
  "name": "My Plugin",
  "version": "1.0.0",
  "author": "you",
  "description": "What it does.",
  "minimum_app_version": "0.1.0",
  "entry_point": "plugin.py:MyPlugin",
  "permissions": ["register_detector", "import_knowledge"],
  "dependencies": []
}
```

`entry_point` is `file.py:ClassName` (defaults to `__init__.py` if no file).
`minimum_app_version` is checked against the running app; incompatible plugins
are skipped during discovery.

## plugin.py

```python
from pentest_workstation.app.plugins.api import Plugin, PluginContext

class MyPlugin(Plugin):
    id = "my-plugin"
    name = "My Plugin"
    version = "1.0.0"

    def setup(self, ctx: PluginContext) -> None:
        ctx.register_detector(MyDetector())          # app/validation/detectors/base.py
        ctx.register_tool_adapter(MyAdapter())        # app/tools/adapters/base.py
        ctx.register_ui_page("my_page", "My Page", lambda app: MyWidget(app))
        ctx.register_report("my_report", "My Report", render_fn)
        ctx.import_records("techniques", [{ "slug": "x", "name": "X" }])
```

`PluginContext` is the only surface a plugin should use. It can register
validation detectors, tool adapters, UI pages, report generators and import
knowledge records.

## Module interfaces

For larger integrations, implement a stable contract from `plugins/api.py`:
`ReconModule`, `NetworkScannerModule`, `DomainIntelligenceModule`,
`OSINTModule`, `VulnerabilityModule`, `ReportModule`. This lets future security
projects become Pen-Lab modules without core changes.

## Discovery & state

`PluginManager` searches the bundled `plugins/` directory and the user plugins
directory. Loaded plugins are recorded in the `plugins` table with their enabled
state and declared permissions.

## Trust model

Plugins run **in-process as trusted Python code**. Declared `permissions` are
surfaced in the UI for transparency; they are not a sandbox. Only install
plugins you trust. See the working example in
`plugins/example_headers_plugin/` (a deterministic security-headers detector).
