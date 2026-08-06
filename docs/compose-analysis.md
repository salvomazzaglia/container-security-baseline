# Compose analysis

## Scope

Compose analysis evaluates declared service and project configuration for
least-privilege and secure-configuration signals. It is **static** and
**offline**. Findings indicate **potential exposure** or baseline gaps that
**require review**.

## Pipeline

1. Load YAML or JSON with parser limits (`config/default.config.json`).
2. Normalize into an internal Compose model (`compose_model.py`).
3. Run Compose rules from `config/rules.json` filtered by policy profile.
4. Apply secret detection to relevant string fields (values redacted).
5. Emit findings with service name, property path, and fingerprint when available.

## Categories covered

Privilege · Host access · Isolation · Capabilities · Identity · Filesystem ·
Secrets · Networking · Resources · Reliability · Logging · Image provenance ·
Build security · Configuration trust

## Notable Critical detections

| ID | Signal |
|----|--------|
| CSB-CMP-001 | `privileged: true` |
| CSB-CMP-002 | Docker/Podman socket bind mount |
| CSB-CMP-003 | Host root filesystem bind mount |
| CSB-CMP-007 | `pid: host` |
| CSB-CMP-020 | `cap_add` includes `ALL` |
| CSB-CMP-024 | seccomp unconfined |
| CSB-CMP-050 | Secret-like environment literal |
| CSB-CMP-114 | Credentials embedded in image reference |

## Trust and incompleteness

Because interpolation is not resolved and referenced files are not read,
absence of a finding does **not** mean the effective runtime config is safe.
See [compose-trust-model.md](compose-trust-model.md).

## Recommended remediation posture

Remediations are **recommended** changes (for example: drop privileged mode,
avoid socket mounts, pin digests under strict policy). Validate in a
non-production environment. Use `suggest` only as a starting point for review.
