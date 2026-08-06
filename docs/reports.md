# Reports

## Formats

| Format | Writer | Typical path |
|--------|--------|--------------|
| JSON | `json_report.py` | `report.json` |
| HTML | `html_report.py` | `report.html` |
| SARIF | `sarif_report.py` | `report.sarif` |

Select with `--format json|html|sarif|all` (default `all`).
Output directory: `--output-directory` (default `reports`).

## Common contents

- Tool name/version and synthetic marker when `--synthetic` is set
- Input summary (paths masked in default privacy mode)
- Policy name, fail_on, minimum_score
- Parsing status and warnings
- Result / severity / category counts
- Score, grade, score explanation, highest severity
- Findings (redacted evidence)
- Suppression audit entries
- Unavailable checks, recommendations, limitations
- Exit code used for the run

## Privacy modes

| Mode | Behavior |
|------|----------|
| `masked` (default) | Mask absolute user paths; redact secrets |
| `full` | Less path masking; prints a console privacy warning |

Never share full-mode reports containing real host paths publicly.

## Schemas

- `schemas/report.schema.json`
- `schemas/finding.schema.json`
- `schemas/sarif-subset.schema.json`

## Console summary

`console.py` prints a concise summary unless `--quiet` is set. Use `--verbose`
for additional detail.

## Sample artifacts

Public samples under `examples/` (when generated) and the screenshot at
`docs/images/sample-container-security-report.png` use **synthetic** data only.
