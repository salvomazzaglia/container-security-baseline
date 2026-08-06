# Synthetic Compose examples

Offline fixtures for `container-security-baseline`. Every hostname, registry,
secret, and service name is synthetic. Nothing here is meant to be executed
with Docker.

## Files

| File | Purpose |
|------|---------|
| `insecure-compose.yml` | Intentionally insecure patterns (privileged, docker.sock, host namespaces, secrets in env, unbounded logging, etc.) |
| `hardened-compose.yml` | Hardened demo patterns (non-root, cap_drop, digest pins, internal networks, secrets). Synthetic demo — not universally production-ready. |
| `mixed-compose.yml` | Mix of good and bad practices across services |
| `compose-with-anchors.yml` | YAML anchors/aliases for informational/parser rules |
| `compose.json` | JSON-format Compose equivalent (simple synthetic stack) |

## Service names

`synthetic-web`, `synthetic-api`, `synthetic-database`, `synthetic-worker`,
`synthetic-admin`, `synthetic-monitor`

## Placeholders

- Registry: `registry.example.invalid`
- Domains: `example.invalid`
- Fake secrets: `SYNTHETIC_NOT_A_REAL_SECRET`

## Usage

Point the scanner at a file or this directory. Do not invoke Docker.
