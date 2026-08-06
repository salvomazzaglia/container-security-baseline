# Final release checklist — v1.0.0

## Package and CLI

- [x] `pyproject.toml` metadata version 1.0.0
- [x] Package layout under `src/container_security_baseline/`
- [x] CLI entry point `container-security-baseline`
- [x] Commands: scan, validate, list-rules, explain, suggest, compare, generate-demo, version
- [x] Exit codes 0/1/2/3 documented and implemented

## Rules and policy

- [x] `config/rules.json` with 90+ Compose and 45+ Dockerfile rules
- [x] Policies: baseline, strict, development
- [x] Scoring + suppressions + redaction modules present

## Examples and schemas

- [x] Synthetic Compose/Dockerfile examples under `examples/`
- [x] JSON schemas under `schemas/`
- [ ] Sample reports (`examples/sample-report.*`) generated and marked synthetic
- [ ] Sample remediation patch generated
- [ ] Screenshot at `docs/images/sample-container-security-report.png`

## Quality gates

- [ ] `pip install -e ".[dev]"` succeeds in clean venv
- [ ] Ruff lint + format check pass
- [ ] mypy passes
- [ ] pytest suite passes (meaningful coverage)
- [ ] CI workflow present (GitHub-hosted only, no Docker, no secrets)

## Documentation and GitHub metadata

- [x] README (39 sections + three required blockquotes)
- [x] CHANGELOG, CONTRIBUTING, SECURITY
- [x] docs/* suite listed in project brief
- [x] `.github/workflows/ci.yml`, Dependabot, issue/PR templates

## Security / privacy

- [ ] Security audit checklist completed (`docs/security-audit-v1.0.0.md`)
- [ ] Repository guards confirm synthetic-only tracked configs
- [ ] No real secrets, host paths, registries, or Portainer stacks tracked

## Release logistics (manual)

- [ ] Local validation on Windows and Linux as available
- [ ] Git initialized with GitHub noreply identity
- [ ] Remote repository / push / GitHub release (after confirmation)

Items unchecked remain for final verification before public release tagging.
