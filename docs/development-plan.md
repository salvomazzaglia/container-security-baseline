# Development Plan — container-security-baseline 1.0.0

## Objective

Build a cross-platform, offline static-analysis toolkit that assesses Docker
Compose and Dockerfile **configuration baselines**, produces secret-safe
reports (JSON/HTML/SARIF), supports policy gates via transparent scoring and
exit codes, and ships with synthetic examples suitable for a public portfolio.

## Constraints

- Never invoke Docker/Podman or access the Docker socket
- Never make network or registry requests
- Never resolve Compose interpolation or follow include/extends
- Never read referenced env_file/secrets/configs contents
- Never auto-apply remediation to input files
- Synthetic data only in tracked examples
- GitHub-hosted CI only (`contents: read`, no secrets)

## Terminology

Use: static analysis, offline, configuration baseline, potential exposure,
requires review, recommended remediation, defense in depth.

Do not claim: CIS/NIST certification, container is secure, vulnerability-free
images, runtime verification, official Docker product status.

## Phases

| Phase | Work |
|------:|------|
| 1 | Inspect directory; write this plan |
| 2 | Repository structure and metadata |
| 3 | Models, statuses, severities, paths, locations |
| 4 | Safe YAML and JSON parsers |
| 5 | Normalized Compose model |
| 6 | Conservative Dockerfile parser |
| 7 | Configuration, policy, and schema validation |
| 8 | Secret detection and complete redaction |
| 9 | Rule registry |
| 10 | Compose rules |
| 11 | Dockerfile rules |
| 12 | Scoring |
| 13 | Suppressions |
| 14 | Findings and aggregation |
| 15 | Remediation guidance |
| 16 | Safe proposed-diff generation |
| 17 | Comparison |
| 18 | JSON, HTML, SARIF, and console reports |
| 19 | CLI |
| 20 | Deterministic synthetic examples |
| 21 | Sample reports and patch |
| 22 | Screenshot |
| 23 | Meaningful pytest suite |
| 24 | Ruff and mypy |
| 25 | GitHub-hosted CI |
| 26 | Complete documentation |
| 27 | Isolated virtual environment |
| 28 | Install development dependencies |
| 29 | Complete local validation |
| 30 | Synthetic demo workflows only |
| 31 | Security/privacy audit |
| 32 | Defect fixes and revalidation |
| 33 | Git initialization with privacy-safe metadata |

**Status (2026-08-06):** Implementation and documentation for v1.0.0 are in
progress across parallel workstreams. Phases 26+ (local validation, audit
finalization, git init) remain operator-side where noted in
`docs/final-release-checklist.md` and `docs/security-audit-v1.0.0.md`.

## Success criteria

- Offline scan of synthetic Compose/Dockerfile fixtures produces reports
- Policy fail thresholds map to documented exit codes
- Secrets appear only as redacted evidence / fingerprints
- CI runs without Docker and without repository secrets
- Docs avoid unsupported security guarantees

See `docs/final-release-checklist.md`.
