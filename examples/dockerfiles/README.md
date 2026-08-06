# Synthetic Dockerfile examples

Offline fixtures for `container-security-baseline`. Images, digests, and
secret-like values are synthetic placeholders only. Do not build or run.

## Files

| File | Purpose |
|------|---------|
| `Dockerfile.insecure` | latest base, root, secret-like ARG, curl\|shell, chmod 777, `COPY . .`, shell-form ENTRYPOINT |
| `Dockerfile.hardened` | digest-pinned multi-stage, non-root, minimal COPY, exec-form ENTRYPOINT, HEALTHCHECK |
| `Dockerfile.multistage` | Multi-stage synthetic build (deps → build → runtime) |

## Placeholders

- Registry: `registry.example.invalid`
- Fake digest: `sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
- Fake secrets: `SYNTHETIC_NOT_A_REAL_SECRET`

## Usage

Scan these files with the Dockerfile analyzer. Do not invoke Docker.
