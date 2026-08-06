# Threat model

## Purpose

Describe threats relevant to an offline Compose/Dockerfile static analyzer and
the mitigations built into v1.0.0. This is not a formal STRIDE certification.

## Assets

| Asset | Sensitivity |
|-------|-------------|
| Compose files | May contain secret-like literals and host paths |
| Dockerfiles | May embed credentials or supply-chain patterns |
| Secret references | Paths/names only — content must not be read |
| Build configuration | Context paths, args, entitlements |
| Reports (JSON/HTML/SARIF) | Shareable only when redacted |
| Suppression files | Encode risk acceptance decisions |
| Policy files | Define fail thresholds and scoring |
| CI results / artifacts | Must remain synthetic in public demos |

## Threat actors and failure modes

| Threat / failure | Impact | Mitigation | Residual risk |
|------------------|--------|------------|---------------|
| Malicious Compose author | Misleading configs; DoS via YAML | Resource limits; reject custom tags; duplicate-key rejection | Ambiguous Compose semantics remain |
| Compromised repository | Malicious rules/scripts | Code review; CI contents:read; Dependabot | Supply-chain of third-party actions |
| Accidental secret commit | Credential exposure | Redaction; repo guards; CONTRIBUTING policy | Operator may still commit real files |
| Unsafe YAML payload | Code execution / DoS | Safe loader path; alias/node/depth caps | Extreme documents may still fail parse |
| YAML resource exhaustion | CI hang / OOM | Parser limits in config | Limits are configurable — misuse possible |
| Path traversal | Read outside project | `safe_resolve_path`; project-root checks | Mis-set `--project-root` expands scope |
| Symlink escape | Same as traversal | Symlink target must stay in root | Complex link graphs may error out |
| Secret leakage in reports | Credential disclosure | Never store values; `[REDACTED]` evidence | `--privacy-mode full` weakens path masking |
| Unsafe remediation | Broken or harmful config | Propose-only diffs; refuse anchors/secrets-nearby | Operator may apply without review |
| Misleading score | False confidence | Explicit non-certification messaging; partial flag | Operators may still over-trust grade |
| Suppression abuse | Hide Critical issues | Critical requires policy flag + stronger justification | Enabled policy may allow Critical suppressions |
| Parser ambiguity | Missed or extra findings | Conservative detection; Unavailable/Warning statuses | Compose runtime may differ |
| Supply-chain action compromise | CI integrity | Prefer SHA pins; majors documented when unverified | Major tags are mutable |
| Operator false confidence | Deploy despite risks | Limitations in every report; docs terminology | Social/process risk remains |

## Trust boundaries

1. **Operator → tool:** Inputs are untrusted as code; treated as data to parse.
2. **Tool → filesystem:** Only explicit paths under project root.
3. **Tool → reports:** Outbound artifacts must not contain secret values.
4. **CI → world:** No Docker socket, no secrets, no network analysis features.

## Residual risk statement

Static analysis of configuration cannot prove runtime safety. Host mitigations,
image contents, orchestrator policies, and application logic are outside this
threat model’s enforcement surface.
