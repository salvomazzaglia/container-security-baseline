# Secret handling

## Goals

Detect **potential** secret exposure in Compose/Dockerfile text while ensuring
reports never contain raw secret values.

## Detection

`secret_detection.py` combines:

- Key-name heuristics (`PASSWORD`, `TOKEN`, `API_KEY`, …)
- Known token-ish shapes (synthetic-friendly patterns)
- Private key header markers
- URL userinfo credentials
- Optional high-entropy checks (length + Shannon threshold from config)

Allowlisted placeholder values (for example `changeme`, `example`, `redacted`)
reduce noise on demos.

## Redaction

- Evidence fields use `[REDACTED]` (or equivalent markers)
- Values are **never** stored on findings
- Optional SHA-256 **fingerprints** (short prefix) support deduplication only —
  fingerprints are not reversible secrets

## What is not read

| Source | Behavior |
|--------|----------|
| `env_file` paths | Not opened |
| Compose `secrets:` file sources | Not opened |
| `configs:` file sources | Not opened |
| Host credential stores | Not accessed |
| Registries / vault APIs | No network |

A reference to an env/secret file may still produce a finding about trust or
path safety without reading file contents.

## False positives

Heuristic hits are **potential exposure** signals. Confirm before rotating
credentials. Use suppressions when a value is a known non-secret.

## Safe report sharing

- Prefer `--privacy-mode masked` (default)
- Do not share `--privacy-mode full` outputs publicly
- Strip local paths before attaching reports to tickets when needed
- Synthetic demos use `SYNTHETIC_NOT_A_REAL_SECRET` and `*.example.invalid`
