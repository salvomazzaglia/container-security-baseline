# CI integration

## Workflow

`.github/workflows/ci.yml` runs on:

- `push` to `main`
- `pull_request`
- `workflow_dispatch`

## Hard requirements

| Requirement | Implementation |
|-------------|----------------|
| GitHub-hosted runners only | `ubuntu-latest`, `windows-latest` |
| Permissions | `contents: read` |
| No secrets | Workflow does not reference `${{ secrets.* }}` |
| No `pull_request_target` | Not used |
| No Docker | No docker install, socket, build, or run |
| Matrix | OS × Python 3.11 / 3.12 |

## Steps

1. Checkout (`actions/checkout@v4`)
2. Setup Python (`actions/setup-python@v5`)
3. `pip install -e ".[dev]"`
4. Ruff lint + format check
5. mypy
6. pytest
7. Generate synthetic demos/reports
8. Schema validation
9. Repository guards
10. Package build
11. Upload artifacts (`actions/upload-artifact@v4`)

## Action pinning note

Prefer official actions pinned to verified full-length commit SHAs. When SHA
verification cannot be completed, stable major tags are used and documented in
the workflow comments.

## Using the tool as a gate

```bash
container-security-baseline scan \
  --compose path/to/compose.yml \
  --policy baseline \
  --format json \
  --output-directory reports
```

Interpret exit codes per [exit-codes.md](exit-codes.md). Expect code **2** on
intentionally insecure fixtures under strict/baseline High+ thresholds.

## Privacy

Only synthetic examples should be analyzed in public CI. Do not mount
production Compose files into open repositories.
