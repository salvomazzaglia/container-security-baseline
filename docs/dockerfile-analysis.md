# Dockerfile analysis

## Scope

Dockerfile analysis is a conservative, offline parse of instruction text. It
does not build images, execute `RUN` commands, or inspect layer contents.

## Pipeline

1. Load file under project-root safety rules.
2. Parse instructions into stages (`dockerfile_parser.py`).
3. Evaluate Dockerfile rules (`dockerfile_rules.py` + `config/rules.json`).
4. Redact secret-like fragments in evidence fields.

## Categories covered

Image provenance · Identity · Secrets · Supply chain · Package management ·
Filesystem · Process model · Build context

## Notable Critical / High detections

| ID | Severity | Signal |
|----|----------|--------|
| CSB-DF-020 | Critical | Secret-like `ENV` |
| CSB-DF-022 | Critical | Secret literal in instructions |
| CSB-DF-023 | Critical | COPY/ADD sensitive credential files |
| CSB-DF-021 | High | Secret-like `ARG` |
| CSB-DF-024 | High | Secret via ARG instead of BuildKit secrets |
| CSB-DF-025 | High | Secret removed in later layer (still in history risk) |
| CSB-DF-011 | High | Final `USER` is root |
| CSB-DF-012 | High | USER switched back to root |
| CSB-DF-030 | High | Remote `ADD` URL |
| CSB-DF-032 | High | curl/wget piped to shell |
| CSB-DF-034 | High | Package verification disabled |
| CSB-DF-035 | High | TLS verification disabled |
| CSB-DF-050 | High | `chmod 777` |
| CSB-DF-066 | High | HEALTHCHECK secret fragments |
| CSB-DF-073 | High | Parent traversal in COPY/ADD |

## Limitations

- Multi-stage graphs are modeled conservatively; some cross-stage flows may be
  Informational only.
- Package and supply-chain rules are heuristic — they flag **potential**
  insecure patterns that require review.
- Digest pinning and non-root identity expectations vary by policy profile.

See [rule-catalog.md](rule-catalog.md) and
[standards-and-limitations.md](standards-and-limitations.md).
