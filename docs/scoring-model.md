# Scoring model

## Purpose

Provide a transparent **prioritization aid** for configuration findings. The
score is **not** a security certification and does not prove compliance with
CIS, NIST, or vendor benchmarks.

## Algorithm

Implemented in `scoring.py` (`calculate_score`):

1. Start at **100** (or `starting_score` / policy-configured starting value).
2. Deduplicate findings.
3. For each unique finding with status Fail or Warning that is **not**
   suppressed:
   - Subtract the severity deduction from the policy map.
4. Clamp to **0–100**.
5. Assign a letter grade.
6. Mark **partial** if parse/evaluation errors occurred.

Statuses that do **not** deduct: Pass, Not Applicable, Unavailable, Error,
Suppressed.

Passing rules do **not** inflate the score — the model only subtracts from the
starting value.

## Default deductions

| Severity | Amount |
|----------|-------:|
| Critical | 25 |
| High | 15 |
| Medium | 7 |
| Low | 2 |
| Informational | 0 |

Configured via policy `scoring_deductions` and/or `config/default.config.json`.

## Grades

| Grade | Score |
|-------|------:|
| A | ≥ 90 |
| B | ≥ 80 |
| C | ≥ 70 |
| D | ≥ 50 |
| F | < 50 |

## Suppressions

Suppressed findings remain visible in reports for audit but **do not** reduce
the score. Critical suppressions may be rejected by policy, which can produce
exit code 2 (policy failure) rather than silently improving the score.

## Partial analysis

When parsing or evaluation errors occur, the score explanation notes partial
analysis. Treat partial scores as incomplete — re-run after fixing inputs.

## Project aggregation

One report aggregates findings across all supplied Compose and Dockerfile
inputs for the run. Deduplication uses finding fingerprints where available so
the same issue is not deducted repeatedly.

## Why this is not compliance

- Rules are inspired by common least-privilege practices, not a certified
  checklist mapping.
- Runtime and image contents are out of scope.
- Heuristics (especially secrets) flag **potential exposure** requiring review.
