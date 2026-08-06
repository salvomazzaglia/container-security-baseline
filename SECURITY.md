# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report privately via [GitHub Security Advisories](https://github.com/salvomazzaglia/container-security-baseline/security/advisories/new)
when enabled, or contact the maintainer through
[https://github.com/salvomazzaglia](https://github.com/salvomazzaglia).

Include:

- Affected version (`VERSION` / package version)
- Python and OS versions
- A minimal reproduction using **synthetic or redacted** data only
- Impact assessment (for example: secret leakage, path escape, parser DoS, rule bypass)

You should receive an acknowledgement within 7 days when contact channels are monitored.

## In-scope concerns

| Area | Examples |
|------|----------|
| **Parser vulnerabilities** | Unsafe YAML loading, alias bombs, excessive nesting, custom tags |
| **Secret leakage** | Unredacted values in reports, logs, SARIF, HTML, or diffs |
| **Unsafe patches** | Auto-application to inputs; destructive or ambiguous rewrites |
| **Path traversal** | Escape from `--project-root`; symlink follow outside root |
| **YAML denial of service** | Resource exhaustion via crafted documents |
| **Rule bypass** | Logic errors that miss Critical host/privilege exposures under documented detection |
| **Suppression abuse** | Accepting Critical suppressions without policy controls or audit trail |

## Out of scope / non-vulnerabilities

- Findings on intentionally insecure **synthetic** examples
- Heuristic false positives in secret detection (document via suppressions or issues)
- Absence of image CVE scanning (explicitly out of scope)
- Operator use of `--privacy-mode full` (warned; intentional)

## Project guarantees (and non-guarantees)

This toolkit performs **offline static analysis** of configuration. A score of 100 or grade A is **not** a security certification. Successful scans do not prove containers are secure, images are vulnerability-free, or deployments meet CIS/NIST checklists.

## Responsible disclosure

Please allow reasonable time for a fix before public discussion. Do not attach real production Compose files, credentials, or host paths to public issues or pull requests.
