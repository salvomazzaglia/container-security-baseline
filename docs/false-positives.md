# False positives

## Expectation

Static heuristics will sometimes flag benign configuration. Treat findings as
**potential exposure** signals that **require review**, not automatic proof of
compromise.

## Common sources

| Area | Why it happens | Operator response |
|------|----------------|-------------------|
| Secret-like keys | Names such as `AUTH_MODE` match key patterns | Confirm value is non-secret; suppress with justification |
| High entropy | Random IDs/tokens in demos | Use allowlisted placeholders; suppress if intentional |
| `latest` tags | Common in local dev Compose | Accept under development profile or pin tags |
| Missing resource limits | Often omitted in labs | Strict policy elevates; baseline may remain Low |
| Host mounts in tooling | Observability/debug sidecars | Document compensating controls via suppressions |
| Root USER in build stages | Intermediate stages | Ensure **final** stage is non-root; review DF-011/012 |
| curl\|sh in install docs copied into Dockerfile | Pattern match | Replace with verified downloads |

## Reducing noise

1. Choose the right **policy profile** (development vs baseline vs strict).
2. Prefer severity overrides in a **local** policy file (gitignored) over
   disabling Critical rules.
3. Use **scoped suppressions** (service + property_path + fingerprint).
4. Keep synthetic fixtures clearly labeled to avoid confusing demos with prod.

## Reporting false positives

Open a feature/bug issue with a **synthetic** minimal Compose/Dockerfile
reproducer. Do not attach real secrets.
