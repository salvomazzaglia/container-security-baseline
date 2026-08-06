# Input safety

## Project root

All analysis paths are resolved relative to `--project-root`. Escapes outside
the root raise `PathSafetyError` (exit code **3**).

## Symlinks

- Following symlinks for analysis is disabled by default configuration
  (`analysis.follow_symlinks: false`)
- Symlink targets that escape the project root are rejected
- Directory symlinks are not followed as traversal roots

## Parser limits

`config/default.config.json` enforces bounded YAML/JSON parsing, including:

- Maximum file bytes, depth, nodes, aliases
- Maximum scalar/sequence/mapping sizes
- Single-document Compose YAML by default
- Reject duplicate keys and custom tags

These limits reduce YAML denial-of-service and unsafe-tag risks.

## Analysis flags (hard offline posture)

| Flag | Default |
|------|---------|
| `invoke_docker` | false |
| `network_access` | false |
| `resolve_interpolation` | false |
| `read_referenced_files` | false |

## Source loading

`source.py` checks size, encoding, and rejects NUL-heavy / unsafe payloads
before parsing.

## Operator guidance

- Point `--project-root` at the smallest directory that contains intended inputs
- Do not scan home directories or production mount trees “just in case”
- Keep real secrets out of tracked examples and CI artifacts
