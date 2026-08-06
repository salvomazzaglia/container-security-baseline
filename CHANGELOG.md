# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-06

### Added

- Offline static-analysis CLI for Docker Compose YAML/JSON and Dockerfiles
- Rule catalog with 90+ Compose and 45+ Dockerfile checks (`config/rules.json`)
- Policy profiles: `baseline`, `strict`, and `development`
- Transparent scoring (0–100) with letter grades and partial-analysis marking
- Governed suppressions with expiration, ownership, and Critical restrictions
- Privacy-preserving secret detection with redacted evidence and fingerprints
- JSON, standalone HTML, and SARIF 2.1 subset reports
- `suggest` proposed unified diffs (Compose YAML; never auto-applied)
- `compare` before/after finding and score delta reports
- Safe path resolution within `--project-root` (symlink escape rejection)
- Conservative YAML limits (depth, aliases, custom tags, duplicate keys)
- Synthetic examples under `examples/` and JSON schemas under `schemas/`
- GitHub Actions CI on GitHub-hosted ubuntu/windows × Python 3.11/3.12
- Documentation suite under `docs/`
- MIT license

### Security

- Never invokes Docker/Podman or accesses the Docker socket
- Never resolves interpolation or reads referenced env/secret/config files
- Never stores raw secret values in findings or reports
- Path traversal and symlink-escape protections for analysis inputs
- Proposed patches refuse anchors, merge keys, include/extends, and secrets-nearby contexts

### Notes

- Scores and grades are prioritization aids, not security certification
- Tracked demos use synthetic registries (`*.example.invalid`) and placeholder secrets only

[1.0.0]: https://github.com/salvomazzaglia/container-security-baseline/releases/tag/v1.0.0
