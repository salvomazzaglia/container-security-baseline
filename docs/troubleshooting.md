# Troubleshooting

## Exit code 3 (ERROR)

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| `Path escapes project root` | Input outside `--project-root` | Adjust root or paths |
| `Cannot resolve project root` | Missing/invalid directory | Create/fix path |
| Config/policy JSON errors | Invalid schema or keys | Run `validate`; check schemas |
| Compose parse failure | Malformed YAML / limit exceeded | Fix YAML or raise limits cautiously |
| Suppression load failure | Invalid JSON / missing fields | Compare to `suppressions.example.json` |

## Exit code 2 (POLICY_FAILURE)

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| Insecure synthetic demo fails | Expected High/Critical findings | Use for demos; not an app bug |
| Score below minimum | Strict `minimum_score: 70` | Remediate or adjust local policy intentionally |
| Critical suppression rejected | `allow_critical_suppressions` false | Fix finding or enable with governance |

## Exit code 1 (FINDINGS_BELOW)

Findings exist but are below `fail_on`. Review Medium/Low noise; consider
profile choice or scoped suppressions.

## Empty or surprising reports

- Confirm `--compose` / `--dockerfile` paths
- Check `parsing_warnings` and `parsing_status`
- Remember: referenced env/secret files are **not** read
- Interpolation is **not** resolved — literals matter

## Secrets appear redacted but you expected values

By design. Use fingerprints and property paths for correlation. Never request
raw secrets in issues.

## `suggest` produces no useful diff

Common refusals: anchors, include/extends, JSON input, secrets nearby, or
rules that are not `safe` patchable. Apply manual remediation from `explain`.

## CI failures without Docker

Expected — Docker must not be installed or invoked. Fix Python/tooling issues
instead. Ensure synthetic generation scripts exist and succeed.

## Privacy warning on console

Printed when `--privacy-mode full` is selected. Prefer `masked` for shared
artifacts.
