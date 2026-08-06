# Release notes — container-security-baseline 1.0.0

**Date:** 2026-08-06  
**Author:** Salvatore Mazzaglia  
**Repository:** https://github.com/salvomazzaglia/container-security-baseline

## Highlights

- Offline static analysis for Docker Compose YAML/JSON and Dockerfiles
- 90+ Compose and 45+ Dockerfile configuration baseline rules
- Policy profiles: baseline, strict, development
- Transparent scoring with grades; governed suppressions
- Secret-safe JSON, HTML, and SARIF reports
- Proposed remediation diffs that never auto-apply
- GitHub-hosted CI matrix (Windows/Linux × Python 3.11/3.12) without Docker

## Operator impact

Use the tool as a **configuration baseline** gate in review and CI. Interpret
findings as **potential exposure** that **requires review**. A high score is
**not** a security certification.

## Breaking changes

Initial public release — no prior stable API.

## Upgrade notes

N/A (first release).

## Known limitations

See [standards-and-limitations.md](standards-and-limitations.md). Notably: no
image CVE scanning, no runtime inspection, no CIS/NIST certification claims.

## Related portfolio projects

sysadmin-health-check · backup-integrity-verifier · network-device-watch ·
self-hosted-runner-hardening-lab · endpoint-incident-triage
