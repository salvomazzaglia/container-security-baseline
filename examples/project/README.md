# Synthetic mini-project example

Small combined Compose + Dockerfile fixture for project-root scans.
All registries, secrets, and service names are synthetic. Do not build or run.

## Layout

| File | Purpose |
|------|---------|
| `compose.yml` | Compose stack with `synthetic-web` (build + hardened-ish) and `synthetic-api` (intentionally weaker) |
| `Dockerfile` | Digest-pinned non-root image used by `synthetic-web` build |
| `.dockerignore` | Typical ignore patterns for build context hygiene checks |

## Placeholders

- Registry: `registry.example.invalid`
- Fake secrets: `SYNTHETIC_NOT_A_REAL_SECRET`

## Usage

Scan this directory as a project root. Do not invoke Docker.
