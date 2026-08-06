# Rule catalog

Version: **1.0.0** (`config/rules.json`)

Totals: **143** rules — **94** Compose (`CSB-CMP-*`) and **49** Dockerfile
(`CSB-DF-*`). This document summarizes by category, with full detail for
**Critical** and **High**, and compact tables for Medium / Low / Informational.

Use `container-security-baseline list-rules` and `explain <rule_id>` for the
authoritative live fields. Policy profiles may override severity
(`severity_overrides`) or disable rules.

---

## Severity and patchability legend

| Severity | Typical meaning |
|----------|-----------------|
| Critical | Host/privilege or credential exposure with high impact |
| High | Strong isolation or secret-handling weakness |
| Medium | Important baseline gap |
| Low | Hardening / hygiene |
| Informational | Advisory / context |

| Patchability | Meaning |
|--------------|---------|
| `safe` | May appear in proposed unified diff (still requires review) |
| `manual` | Guidance only; no automatic patch proposal |

---

## Critical and High — Compose

| ID | Sev | Category | Title | Detection (summary) | Risk | Remediation | Patch |
|----|-----|----------|-------|---------------------|------|-------------|-------|
| CSB-CMP-001 | Critical | Privilege | privileged mode enabled | `services.*.privileged == true` | Broad host access; weak isolation | Set `privileged: false` or remove | safe |
| CSB-CMP-002 | Critical | Host access | Docker/runtime socket mounted | Bind mount of docker.sock/podman.sock | Often root-equivalent host control | Do not mount runtime sockets; use least-privilege APIs | manual |
| CSB-CMP-003 | Critical | Host access | Host root filesystem bind-mounted | Host `/` bind into container | Host filesystem compromise | Remove root binds; mount scoped subpaths RO | manual |
| CSB-CMP-004 | High | Host access | Sensitive host path mounted read-write | Sensitive paths RW | Alter/expose host credentials/config | Prefer RO mounts or remove; use named volumes | safe |
| CSB-CMP-006 | High | Isolation | network_mode host | `network_mode: host` | Removes network namespace isolation | Use bridge/user-defined networks | manual |
| CSB-CMP-007 | Critical | Isolation | pid host namespace | `pid: host` | Process visibility / attack primitives | Remove unless justified + suppressed | manual |
| CSB-CMP-008 | High | Isolation | ipc host namespace | `ipc: host` | Weakens IPC isolation | Avoid host IPC | manual |
| CSB-CMP-009 | High | Isolation | userns_mode host | `userns_mode: host` | Weakens user namespace isolation | Avoid host userns mode | manual |
| CSB-CMP-010 | High | Host access | device mappings present | `devices:` present | Direct device access to host | Remove unless required; document | manual |
| CSB-CMP-011 | High | Host access | broad device_cgroup_rules | Broad cgroup device rules | Excessive device access | Tighten rules | manual |
| CSB-CMP-020 | Critical | Capabilities | cap_add ALL | `cap_add` includes ALL | Near-privileged capability set | Drop ALL; add minimal caps | manual |
| CSB-CMP-021 | High | Capabilities | dangerous capabilities added | Dangerous caps from config list | Privilege escalation primitives | Remove dangerous caps | manual |
| CSB-CMP-024 | Critical | Capabilities | seccomp unconfined | seccomp unconfined | Disables syscall filtering | Use default/custom profile | manual |
| CSB-CMP-025 | High | Capabilities | AppArmor unconfined | AppArmor unconfined | Disables MAC profile | Use enforcing profile | manual |
| CSB-CMP-027 | High | Capabilities | unsafe proc/sys mounts or sysctls | Sensitive proc/sys mounts | Kernel/parameter exposure | Remove unsafe mounts/sysctls | manual |
| CSB-CMP-031 | High | Identity | explicit root user | `user: 0` / root | Runs as root in container | Non-root user | manual |
| CSB-CMP-033 | High | Identity | credential dirs writable for root container | Writable cred dirs + root | Credential tampering risk | Non-root + RO where possible | manual |
| CSB-CMP-043 | High | Filesystem | bind mount parent traversal | `..` in bind source | Path escape risk | Fix paths; keep under intended root | manual |
| CSB-CMP-050 | Critical | Secrets | secret-like environment literal | Key/value heuristics on env | Credential leakage in Compose | Use secrets manager / Compose secrets | manual |
| CSB-CMP-051 | High | Secrets | high-entropy credential literal | Entropy heuristic | Possible embedded secret | Remove literal; rotate if real | manual |
| CSB-CMP-052 | High | Secrets | secret in command/entrypoint | Secret-like in command | Process/arg exposure | Externalize secrets | manual |
| CSB-CMP-053 | High | Secrets | secret in labels | Secret-like labels | Metadata leakage | Remove secrets from labels | manual |
| CSB-CMP-054 | High | Secrets | secret in build args | Secret-like build args | Build-time leakage | BuildKit secrets | manual |
| CSB-CMP-060 | High | Secrets | insecure interpolation default | Default containing secret-like value | Fallback credential exposure | Remove insecure defaults | manual |
| CSB-CMP-071 | High | Networking | sensitive port published | Sensitive ports published | Service exposure | Bind localhost or remove publish | manual |
| CSB-CMP-072 | High | Networking | host network with ports/privileges | Host net + ports/privs | Amplified exposure | Remove host networking | manual |
| CSB-CMP-087 | High | Secrets | healthcheck secret exposure | Secret-like in healthcheck | Leak via probe command | Remove secrets from probes | manual |
| CSB-CMP-113 | High | Image provenance | HTTP registry reference | `http://` registry | Integrity/confidentiality risk | Use HTTPS registries | manual |
| CSB-CMP-114 | Critical | Image provenance | credentials in image reference | user:pass@ in image ref | Credential theft | Remove embedded creds; use auth helpers | manual |
| CSB-CMP-121 | High | Build security | build context parent traversal | `..` in build context | Context escape | Constrain context | manual |
| CSB-CMP-123 | High | Build security | dockerfile path escapes context | Dockerfile outside context | Unexpected build inputs | Keep Dockerfile in context | manual |
| CSB-CMP-124 | High | Build security | secret-like build args | Secret-like args | Build secret leakage | BuildKit secrets | manual |
| CSB-CMP-125 | High | Build security | privileged/insecure build entitlement | Insecure entitlements | Elevated build privileges | Remove entitlements | manual |
| CSB-CMP-139 | High | Configuration trust | sensitive value via anchors | Anchors carry secret-like data | Hidden reuse of secrets | Avoid secrets in anchors | manual |

**False positives (general):** Legitimate workloads may require elevated
settings; document via suppressions with expiration and review reference.
**Limitations (general):** Static analysis cannot verify runtime enforcement
or host mitigations (rootless, SELinux, etc.).

**Policy notes:** Development profile downgrades some items (for example
`CSB-CMP-007` → High). Strict may raise selected Medium/Low items. See
[policy-profiles.md](policy-profiles.md).

---

## Critical and High — Dockerfile

| ID | Sev | Category | Title | Detection (summary) | Risk | Remediation | Patch |
|----|-----|----------|-------|---------------------|------|-------------|-------|
| CSB-DF-011 | High | Identity | final USER is root | Last USER is root/0 | Root runtime identity | Final non-root USER | manual |
| CSB-DF-012 | High | Identity | USER switched back to root | Later USER root | Privilege reintroduced | Keep final non-root | manual |
| CSB-DF-020 | Critical | Secrets | secret-like ENV | ENV key/value heuristics | Image layer secret leakage | Remove; use runtime secrets | manual |
| CSB-DF-021 | High | Secrets | secret-like ARG | ARG heuristics | Build-arg leakage | BuildKit secret mounts | manual |
| CSB-DF-022 | Critical | Secrets | secret literal in instructions | Literal patterns in RUN/etc. | Persistent secret in layers | Remove literals; rotate if real | manual |
| CSB-DF-023 | Critical | Secrets | COPY/ADD sensitive credential files | Sensitive filenames copied | Creds in image | Do not copy credential files | manual |
| CSB-DF-024 | High | Secrets | secret via ARG instead of BuildKit | Secret-like ARG usage | Weaker secret handling | Prefer BuildKit secrets | manual |
| CSB-DF-025 | High | Secrets | secret removed in later layer | Delete after introduce | History may retain secret | Never introduce secret layers | manual |
| CSB-DF-030 | High | Supply chain | remote ADD URL | `ADD http(s)://` | Unpinned remote content | COPY local verified artifacts | manual |
| CSB-DF-032 | High | Supply chain | curl/wget piped to shell | pipe-to-shell pattern | Arbitrary remote code | Download, verify, then install | manual |
| CSB-DF-034 | High | Supply chain | package verification disabled | Flags disabling verify | Tampered packages | Keep verification enabled | manual |
| CSB-DF-035 | High | Supply chain | TLS verification disabled | insecure TLS flags | MITM risk | Keep TLS verify on | manual |
| CSB-DF-050 | High | Filesystem | chmod 777 | `chmod 777` | World-writable paths | Least privilege modes | manual |
| CSB-DF-066 | High | Secrets | HEALTHCHECK secret fragments | Secret-like in HEALTHCHECK | Probe leakage | Remove secrets from HEALTHCHECK | manual |
| CSB-DF-073 | High | Build context | parent traversal in COPY/ADD | `..` in sources | Context escape | Fix paths | manual |

---

## Medium / Low / Informational — Compose (summary)

| ID | Sev | Category | Title |
|----|-----|----------|-------|
| CSB-CMP-005 | Medium | Host access | Sensitive host path mounted read-only |
| CSB-CMP-012 | Medium | Filesystem | volumes_from used |
| CSB-CMP-013 | Low | Networking | legacy links or external_links |
| CSB-CMP-022 | Informational | Capabilities | cap_drop missing |
| CSB-CMP-023 | Low | Capabilities | cap_drop does not include ALL |
| CSB-CMP-026 | Medium | Capabilities | no-new-privileges missing |
| CSB-CMP-028 | Medium | Capabilities | unsafe sysctl values |
| CSB-CMP-030 | Medium | Identity | no explicit service user |
| CSB-CMP-032 | Medium | Identity | privileged supplementary groups |
| CSB-CMP-040 | Low | Filesystem | read_only not enabled |
| CSB-CMP-041 | Low | Filesystem | writable root filesystem undocumented |
| CSB-CMP-042 | Informational | Filesystem | tmpfs advisory with read_only |
| CSB-CMP-044 | Informational | Filesystem | absolute host bind path |
| CSB-CMP-045 | Medium | Filesystem | bind source outside project root |
| CSB-CMP-046 | Low | Filesystem | ambiguous short volume syntax |
| CSB-CMP-047 | Informational | Filesystem | volume mode missing |
| CSB-CMP-055 | Medium | Secrets | env_file reference |
| CSB-CMP-056 | Medium | Secrets | secret-like path as volume |
| CSB-CMP-057 | Informational | Secrets | top-level secret unused |
| CSB-CMP-058 | Informational | Secrets | service secret policy expectation |
| CSB-CMP-059 | Medium | Secrets | unsafe secret source path |
| CSB-CMP-070 | Medium | Networking | port published on all interfaces |
| CSB-CMP-073 | Informational | Networking | backend network not internal |
| CSB-CMP-074 | Informational | Networking | service attached to all networks |
| CSB-CMP-075 | Informational | Networking | extra_hosts host-gateway |
| CSB-CMP-076 | Informational | Networking | static public DNS |
| CSB-CMP-077 | Informational | Networking | static mac/addressing |
| CSB-CMP-080 | Low | Resources | no memory limit |
| CSB-CMP-081 | Low | Resources | no CPU limit |
| CSB-CMP-082 | Low | Resources | no PID limit |
| CSB-CMP-083 | Medium | Resources | PID limit disabled/unlimited |
| CSB-CMP-084 | Low | Resources | inconsistent resource limits |
| CSB-CMP-085 | Medium | Reliability | no healthcheck |
| CSB-CMP-086 | Medium | Reliability | healthcheck disabled |
| CSB-CMP-088 | Informational | Reliability | depends_on service_started vs healthy |
| CSB-CMP-089 | Informational | Reliability | restart policy absent |
| CSB-CMP-090 | Low | Reliability | unbounded restart behavior |
| CSB-CMP-091 | Informational | Reliability | stop_grace_period advisory |
| CSB-CMP-100 | Informational | Logging | logging driver/options absent |
| CSB-CMP-101 | Low | Logging | json-file without max-size |
| CSB-CMP-102 | Low | Logging | json-file without max-file |
| CSB-CMP-103 | Informational | Logging | logging disabled |
| CSB-CMP-104 | Informational | Logging | remote logging target |
| CSB-CMP-110 | Medium | Image provenance | image uses latest tag |
| CSB-CMP-111 | Medium | Image provenance | image has no explicit tag |
| CSB-CMP-112 | Low | Image provenance | image not digest-pinned |
| CSB-CMP-115 | Informational | Image provenance | interpolation-only image reference |
| CSB-CMP-120 | Low | Build security | broad build context |
| CSB-CMP-122 | Medium | Build security | absolute build context |
| CSB-CMP-126 | Informational | Build security | build SSH forwarding |
| CSB-CMP-127 | Medium | Build security | build secrets absent with secret-like args |
| CSB-CMP-130 | Medium | Configuration trust | include used |
| CSB-CMP-131 | Medium | Configuration trust | extends.file used |
| CSB-CMP-132 | Medium | Configuration trust | env_file outside project root |
| CSB-CMP-133 | Medium | Configuration trust | configs.file outside project root |
| CSB-CMP-134 | Medium | Configuration trust | secrets.file outside project root |
| CSB-CMP-135 | Informational | Configuration trust | label_file used |
| CSB-CMP-136 | Medium | Configuration trust | credential_spec.file used |
| CSB-CMP-137 | Informational | Configuration trust | security-related extension fields |
| CSB-CMP-138 | Informational | Configuration trust | YAML anchors or merge keys |

---

## Medium / Low / Informational — Dockerfile (summary)

| ID | Sev | Category | Title |
|----|-----|----------|-------|
| CSB-DF-001 | Medium | Image provenance | FROM uses latest |
| CSB-DF-002 | Medium | Image provenance | FROM has no tag |
| CSB-DF-003 | Low | Image provenance | FROM not digest-pinned |
| CSB-DF-004 | Informational | Image provenance | FROM scratch |
| CSB-DF-005 | Informational | Image provenance | ARG used in FROM unresolved |
| CSB-DF-006 | Medium | Image provenance | suspicious registry reference |
| CSB-DF-010 | Medium | Identity | no final USER |
| CSB-DF-013 | Informational | Identity | numeric non-root USER |
| CSB-DF-031 | Low | Supply chain | ADD where COPY clearer |
| CSB-DF-033 | Medium | Supply chain | download without checksum |
| CSB-DF-036 | Medium | Supply chain | git clone unpinned |
| CSB-DF-040 | Low | Package management | apt-get update separated |
| CSB-DF-041 | Low | Package management | apt missing no-install-recommends |
| CSB-DF-042 | Low | Package management | package cache not cleaned |
| CSB-DF-043 | Medium | Package management | unbounded system upgrade |
| CSB-DF-044 | Informational | Package management | packages without version pins |
| CSB-DF-045 | Low | Package management | apk missing --no-cache |
| CSB-DF-046 | Medium | Package management | debug tools in final stage |
| CSB-DF-051 | Medium | Filesystem | recursive chmod/chown broad paths |
| CSB-DF-052 | Informational | Filesystem | COPY --chown absent |
| CSB-DF-053 | Informational | Filesystem | WORKDIR absent |
| CSB-DF-054 | Medium | Filesystem | WORKDIR sensitive path |
| CSB-DF-055 | Informational | Filesystem | VOLUME sensitive path |
| CSB-DF-056 | Informational | Filesystem | build artifacts in final stage |
| CSB-DF-060 | Low | Process model | shell-form ENTRYPOINT |
| CSB-DF-061 | Low | Process model | shell-form CMD |
| CSB-DF-062 | Medium | Process model | SSH/systemd/supervisor process |
| CSB-DF-063 | Informational | Process model | no ENTRYPOINT or CMD |
| CSB-DF-064 | Low | Process model | HEALTHCHECK missing |
| CSB-DF-065 | Medium | Process model | HEALTHCHECK NONE |
| CSB-DF-070 | Medium | Build context | COPY/ADD dot with no dockerignore |
| CSB-DF-071 | Medium | Build context | dockerignore missing in project |
| CSB-DF-072 | Low | Build context | dockerignore weak exclusions |
| CSB-DF-074 | Informational | Build context | broad copy from build stage |

---

## References

Rule metadata references Docker Engine security documentation and Compose file
references as educational links. This project is **not** an official Docker
product and is **not** a CIS benchmark implementation.
