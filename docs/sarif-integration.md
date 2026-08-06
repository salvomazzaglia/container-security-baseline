# SARIF integration

## Output

`scan` and `compare` can emit `report.sarif` (SARIF 2.1 subset) via
`--format sarif` or `--format all`.

Schema reference: `schemas/sarif-subset.schema.json`.

## Contents

- Tool driver metadata (`container-security-baseline`, version)
- Rules derived from the rule catalog where applicable
- Results mapped from findings with **redacted** messages
- Locations when file/line data is available

## Intended use

- Local IDE import / offline review
- Artifact retention in CI for humans

## Explicit non-defaults

CI does **not** upload SARIF to GitHub code scanning by default. Enabling
upload would require additional permissions and careful privacy review — out of
scope for the default `contents: read` workflow.

## Limitations

- Subset of SARIF 2.1 — not every SARIF feature is populated
- Secret values never appear in result messages
- SARIF presence does not imply vulnerability database findings
