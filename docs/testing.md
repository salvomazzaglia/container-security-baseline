# Testing

## Goals

Protect parser safety, redaction guarantees, rule correctness, scoring,
suppressions, patch refusal conditions, report schemas, and exit codes — using
**synthetic** fixtures only.

## Layout

```text
tests/
  fixtures/
    compose/
    dockerfiles/
    policies/
    suppressions/
    malformed/
```

## Categories

| Category | Intent |
|----------|--------|
| Parser safety | Limits, duplicate keys, custom tags, oversized inputs |
| Malformed YAML | Graceful error / Unavailable / exit 3 as appropriate |
| Resource-limit fixtures | Alias/depth/node caps |
| Secret redaction | No raw secrets in findings/reports |
| Rule tests | Positive/negative detections per rule or category |
| Patch safety | Refuse anchors/secrets-nearby; never modify inputs |
| Report tests | JSON/HTML/SARIF structure and synthetic markers |
| Scoring / suppressions | Deduction math; Critical rejection |
| Cross-platform | Path masking on Windows and Linux |

## Commands

```bash
python -m pip install -e ".[dev]"
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy
python -m pytest
python -m pytest --junitxml=test-results/junit.xml
```

## CI matrix

GitHub Actions runs the suite on `ubuntu-latest` and `windows-latest` with
Python 3.11 and 3.12. Docker is never required.

## Fixture rules

- Registries: `registry.example.invalid`
- Domains: `example.invalid`
- Secrets: `SYNTHETIC_NOT_A_REAL_SECRET`
- No real host paths, IPs, or credentials
