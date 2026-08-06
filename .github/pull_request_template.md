## Summary

<!-- What does this PR change and why? -->

## Type of change

- [ ] Bug fix
- [ ] New feature / rule
- [ ] Documentation
- [ ] Tests / CI
- [ ] Refactor (no behavior change)
- [ ] Other

## Testing performed

- [ ] `python -m ruff check src tests scripts` passes
- [ ] `python -m ruff format --check src tests scripts` passes
- [ ] `python -m mypy` passes
- [ ] `python -m pytest` passes locally
- [ ] Synthetic demo / sample report generation (if applicable)

## Security / privacy review

- [ ] No real Compose stacks, Dockerfiles, Portainer exports, or host paths
- [ ] No secrets, tokens, credentials, private keys, or certificates
- [ ] No Docker/Podman invocation introduced
- [ ] No automatic remediation of input files
- [ ] Secret evidence remains redacted in reports and tests
- [ ] Path safety / YAML limits preserved

## Documentation

- [ ] README / docs updated when user-facing behavior changes
- [ ] CHANGELOG updated for user-visible changes
- [ ] Rule catalog updated when rules change

## Checklist

- [ ] Code follows project conventions (typed, no eval/exec/pickle/shell=True)
- [ ] Exit codes remain consistent with documented contract
- [ ] Terminology avoids certification / “secure container” claims
- [ ] I confirm this PR does **not** include real infrastructure or sensitive data
