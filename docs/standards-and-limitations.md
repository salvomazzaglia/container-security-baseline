# Standards and limitations

## What this project uses

Common Docker **least-privilege** and secure-configuration principles:

- Avoid privileged mode and host namespace sharing unless justified
- Drop capabilities; enable no-new-privileges where applicable
- Prefer non-root identity
- Avoid embedding secrets in Compose/Dockerfiles
- Prefer pinned images and constrained build contexts
- Bound resources and logging where policy requires

These are implemented as offline static checks — educational and operational
aids for **defense in depth**.

## What this project is not

| Claim | Status |
|-------|--------|
| Official Docker product | **No** |
| CIS Docker Benchmark implementation | **No** |
| NIST checklist certification tool | **No** |
| Runtime / host inspector | **No** |
| Image vulnerability (CVE) scanner | **No** |
| Replacement for application security review | **No** |
| Proof a container is secure | **No** |
| Proof images are vulnerability-free | **No** |

## Technical limitations

- Effective Compose evaluation (interpolation, includes, env files) is incomplete by design
- Host kernel, AppArmor, SELinux, seccomp defaults, rootless mode, and daemon config are not verified unless represented in supplied text
- Image contents and running process state are invisible
- Secret detection is heuristic
- Proposed patches cover a small safe subset of Compose edits
- Scores/grades are prioritization aids only

Every report includes limitation statements derived from
`aggregation.DEFAULT_LIMITATIONS`.
