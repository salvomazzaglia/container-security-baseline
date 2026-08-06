# Configuration

## Files

| File | Role |
|------|------|
| `config/default.config.json` | Tool defaults (parser, analysis, discovery, secrets, scoring, privacy) |
| `config/demo.config.json` | Demo-oriented configuration |
| `config/baseline.policy.json` | Baseline policy profile |
| `config/strict.policy.json` | Strict policy profile |
| `config/development.policy.json` | Development policy profile |
| `config/rules.json` | Rule catalog |
| `config/suppressions.example.json` | Example suppressions document |
| `config/local.*.json` | Local overrides — **gitignored**; never commit secrets |

Schemas: `schemas/config.schema.json`, `schemas/policy.schema.json`,
`schemas/rule.schema.json`, `schemas/suppression.schema.json`.

## CLI selection

```bash
container-security-baseline scan \
  --config config/default.config.json \
  --policy baseline \
  --suppressions path/to/suppressions.json
```

`--policy` accepts a profile name (`baseline`, `strict`, `development`) or a
path to a policy JSON file.

## Important default knobs

### Parser

`maximum_file_bytes`, `maximum_depth`, `maximum_nodes`, `maximum_aliases`,
`reject_duplicate_keys`, `reject_custom_tags`

### Analysis

`follow_symlinks: false`, `read_referenced_files: false`,
`resolve_interpolation: false`, `invoke_docker: false`, `network_access: false`

### Secret detection

`enabled`, `redact_all_values`, entropy thresholds, key patterns

### Reporting / privacy

`privacy_mode: masked`, `mask_absolute_paths: true`

### Remediation

`generate_patches: true`, `refuse_on_anchors: true`, `refuse_on_secrets_nearby: true`

## Validation

```bash
container-security-baseline validate \
  --config config/default.config.json \
  --policy config/baseline.policy.json \
  --compose examples/compose/mixed-compose.yml
```

Invalid configuration or unsafe paths exit with code **3**.
