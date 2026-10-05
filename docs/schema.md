# Database schema

SQLite via SQLAlchemy 2.0. A forward-only migration runner records applied
versions in `schema_migrations`; migration `0001` creates the baseline from the
ORM metadata.

## Design note: techniques vs vulnerabilities

The product brief lists both a `techniques` and a `vulnerabilities` table but
describes a single structured record. Pen-Lab models that as **one rich
`techniques` table**; a vulnerability is a technique whose CWE/OWASP/severity
fields are populated and whose category sits under a vulnerability domain. This
avoids two divergent tables holding the same shape of data.

## Tables

| Table | Purpose |
| --- | --- |
| `categories` | Domain/subcategory tree (self-referential `parent_id`). |
| `techniques` | Rich knowledge records (the knowledge base / vulnerabilities). |
| `references` | External citations with provenance `kind`. |
| `tools` | Tool directory entries (platforms, links, detection metadata). |
| `tool_versions` | Local detection results (status/version/path/last_checked). |
| `payloads` | Structured payloads (context, material class, expected evidence). |
| `wordlists` | Wordlist references (source, license, sample). |
| `workflows`, `workflow_steps` | Guided walkthroughs and their steps. |
| `workflow_progress` | Per-user/engagement step status. |
| `labs` | Practice-lab directory. |
| `cves`, `cwes` | Vulnerability research records. |
| `engagements`, `targets` | Workspaces and authorized, scoped targets. |
| `findings`, `evidence` | Findings and their structured evidence. |
| `plugins` | Installed-plugin registry (enabled state, manifest). |
| `user_notes`, `cheatsheets`, `cheatsheet_entries` | User content. |

Association tables link techniques to tools, payloads, workflows, labs, CVEs,
CWEs and references (`technique_*`), payloads to tools, and CVEs to references.

## Finding lifecycle

`findings.status` ∈ {`not_tested`, `potential`, `suspected`, `validated`,
`confirmed`, `false_positive`, `inconclusive`}. Only `validated` and
`confirmed` are "actionable". `confidence` ∈ {`none`, `low`, `medium`, `high`,
`certain`}. `evidence` stores request/response/diff/payload/timeline/signals/
metrics so every verdict is defensible.
