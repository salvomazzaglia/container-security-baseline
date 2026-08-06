# Contributing

Thank you for contributing to **container-security-baseline**.

## Environment setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate

python -m pip install -U pip
python -m pip install -e ".[dev]"
```

Requirements: Python 3.11+. Do **not** install or invoke Docker for development or CI.

## Branch naming

- `feature/<short-description>`
- `fix/<short-description>`
- `docs/<short-description>`
- `rules/<rule-id-or-category>`

## Coding conventions

- Typed Python under `src/container_security_baseline/`
- Prefer small, testable functions; keep parsers resource-bounded
- No `eval`, `exec`, `pickle`, or `shell=True`
- No network clients; no Docker/Podman subprocesses
- Never print or persist raw secret values — redact first
- Never modify analyzed input files; proposed patches are write-to-output only
- Match existing severity, status, and exit-code contracts

## Rule-ID allocation

| Prefix | Target |
|--------|--------|
| `CSB-CMP-###` | Compose |
| `CSB-DF-###` | Dockerfile |

Allocate the next free ID in the appropriate numeric band. Document the rule fully in `config/rules.json` (title, category, severity, detection logic, risk, remediation, false positives, limitations, profiles, patchability).

## Rule documentation requirements

Every new or changed rule must update:

- `config/rules.json`
- `docs/rule-catalog.md` (at least category summary / Critical–High detail)
- Tests covering positive and negative detection
- Remediation text that recommends review (never “guarantees security”)

## Test requirements

- Add or update pytest coverage for behavior changes
- Use synthetic fixtures only (`*.example.invalid`, `SYNTHETIC_NOT_A_REAL_SECRET`)
- Cover parser safety, redaction, scoring, suppressions, and exit codes where relevant
- Run before opening a PR:

```bash
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy
python -m pytest
```

## Security review

Contributors must ensure changes do not:

- Introduce Docker daemon or network access
- Auto-apply remediation to source files
- Leak secrets into reports, logs, or tests
- Weaken path-safety or YAML resource limits without explicit design review
- Claim CIS/NIST certification or “secure container” guarantees

## Pull-request checklist

- [ ] Tests added/updated and CI passes
- [ ] Ruff and mypy clean
- [ ] Docs / CHANGELOG updated for user-visible changes
- [ ] No real Compose/Dockerfiles, host paths, registries, or credentials
- [ ] No Docker daemon access required
- [ ] No automatic remediation of inputs
- [ ] Exit codes and terminology remain consistent
- [ ] New network features (if any) had explicit design review — default is offline-only

## Sensitive data policy

Never commit:

- Real Compose stacks, Portainer exports, or production Dockerfiles
- `.env`, tokens, private keys, certificates, kubeconfigs, Docker `auth.json`
- Real host mount paths, private IPs, registry namespaces, or usernames
- Local reports under `reports/`, `temp/`, or `local/`

Use `examples/` and `scripts/generate-demo-data.py` for public fixtures.
