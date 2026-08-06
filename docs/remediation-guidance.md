# Remediation guidance

## Principles

- Findings describe **potential exposure** or baseline gaps that **require review**.
- Remediation text is **recommended**, not automatically correct for every app.
- Changes may affect behavior; validate in non-production environments.
- Never treat remediation as proof the workload is secure.

## Sources of guidance

| Source | Content |
|--------|---------|
| Rule `remediation` / `detailed_remediation` | Concise and detailed recommended fixes |
| `explain <rule_id>` | Risk, detection logic, false positives, limitations, operational validation steps |
| `suggest` | Optional proposed unified diff for a small set of safe Compose rules |

## Operational validation steps (default)

1. Apply the proposed change in a review branch.
2. Re-run `container-security-baseline scan`.
3. Deploy to a non-production environment and verify application health.
4. Confirm runtime permissions still meet operational needs.

## Compatibility considerations

Remediation may break workloads that legitimately need elevated privileges,
host networking, or device access. Prefer suppressions with justification when
compensating controls exist — especially for non-Critical findings.

## Related

- [proposed-patches.md](proposed-patches.md)
- [false-positives.md](false-positives.md)
- [rule-catalog.md](rule-catalog.md)
