# Policy profiles

Policies live in `config/*.policy.json` and select fail thresholds, scoring
deductions, requirement flags, and optional severity overrides.

## Profiles

### baseline (`config/baseline.policy.json`)

Balanced production-oriented **configuration baseline**.

| Setting | Value |
|---------|-------|
| `fail_on` | High |
| `minimum_score` | 0 |
| `allow_critical_suppressions` | false |
| `require_non_root` | true |
| `require_no_new_privileges` | true |
| `require_healthcheck` | true |
| `disallow_host_namespaces` | true |
| `disallow_external_file_refs` | true |
| Digest pinning / read-only / cap_drop ALL / resource limits | not required |

### strict (`config/strict.policy.json`)

Stronger least-privilege expectations for hardened deployments.

| Setting | Value |
|---------|-------|
| `fail_on` | Medium |
| `minimum_score` | 70 |
| `require_digest_pinning` | true |
| `require_read_only` | true |
| `require_cap_drop_all` | true |
| `require_resource_limits` | true |
| `require_pid_limit` | true |
| `require_bounded_logging` | true |
| `disallow_wildcard_ports` | true |

Includes severity overrides that elevate selected hygiene findings (for example
resource limits and digest pinning related rules).

### development (`config/development.policy.json`)

Keeps Critical/High isolation findings while relaxing selected development
conveniences (healthcheck required off; several Low/Medium items downgraded to
Informational).

| Setting | Value |
|---------|-------|
| `fail_on` | High |
| `minimum_score` | 0 |
| `require_healthcheck` | false |

## CLI overrides

```bash
container-security-baseline scan --policy strict --fail-on high --minimum-score 80
```

`--fail-on` and `--minimum-score` override the loaded policy for the run.

## Scoring deductions (default across profiles)

| Severity | Deduction |
|----------|----------:|
| Critical | 25 |
| High | 15 |
| Medium | 7 |
| Low | 2 |
| Informational | 0 |

See [scoring-model.md](scoring-model.md) and [exit-codes.md](exit-codes.md).
