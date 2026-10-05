# Resource / import format

Content is authored as YAML under `pentest_workstation/data/` and can be
imported at runtime from YAML, JSON, CSV or Markdown. Every record is validated
against a per-entity field spec; unknown or missing-required fields are rejected
with a precise error (which file, which record, which field).

## Natural keys & upserts

Records upsert by a natural key: `slug` for most entities, `cve_id`/`cwe_id` for
vuln research. Re-importing the same slug updates in place (idempotent).

## File shape

A YAML file is a mapping keyed by the entity name, whose value is a list:

```yaml
techniques:
  - slug: reflected-xss
    name: Reflected Cross-Site Scripting
    category_slug: web-xss        # link to a category by its slug
    severity: high
    cwe: CWE-79
    detection_contract: {detector: reflected_xss}   # wires to a validation detector
    tools: [burpsuite, curl]      # cross-references resolved in a second pass
    payloads: [xss-script-alert]
    cwes: [CWE-79]
```

Cross-reference fields (`tools`, `payloads`, `workflows`, `labs`, `cves`, `cwes`)
list target natural keys and are resolved after all base records load, so file
order does not matter. A reference to a non-existent key is a hard error.

## Entities & key cross-reference fields

| Entity | Key | Notable fields |
| --- | --- | --- |
| categories | slug | domain, name, parent |
| techniques | slug | all methodology fields, detection_contract, refs |
| tools | slug | platforms, website, executable, common_locations, version_args |
| payloads | slug | context, material_class (reference/lab/active), expected_evidence |
| wordlists | slug | source, license, sample |
| workflows | slug | steps (nested list) |
| labs | slug | skill_level, topics, setup_instructions |
| cves | cve_id | cvss_score, source_type, vendor_advisories |
| cwes | cwe_id | name, abstraction, url |
| cheatsheets | slug | entries (nested list) |

## CSV & Markdown

- **CSV** — header row maps to fields; `tags`/`platforms`/`topics`/`capabilities`
  columns split on `;`.
- **Markdown** — supported for cheatsheets: `## Section` headings and fenced code
  blocks become entries.

See `ImportService` (`app/services/import_service.py`) and `SeedLoader`
(`app/database/seed.py`).
