# Suppressions

## Purpose

Document accepted risk for specific findings with ownership, expiration, and
review references. Suppressions are **audited** and remain visible in reports.

## Required fields

From `suppressions.py` / `config/suppressions.example.json`:

| Field | Requirement |
|-------|-------------|
| `id` | Unique non-empty id |
| `rule_id` | Existing rule id |
| `target` | `compose`, `dockerfile`, or related target label — **no wildcards** |
| `justification` | Non-empty explanation |
| `owner_label` | Team/owner label |
| `created_at_utc` | ISO-8601 UTC |
| `expires_at_utc` | Must be after `created_at_utc` |
| `review_reference` | Ticket/PR/advisory id |
| `enabled` | boolean |

Optional matchers: `service`, `property_path`, `fingerprint`.

## Application rules

- Disabled suppressions are ignored (`status: disabled`).
- Expired suppressions are ignored (`status: expired`).
- Unmatched suppressions are audited (`status: unmatched`).
- Wildcard targets (`*`, `all`) are rejected.

## Critical finding restrictions

Critical findings require:

1. Policy `allow_critical_suppressions: true` (default **false** on shipped profiles)
2. Stronger justification (minimum length enforced)
3. Expiration and review reference

Otherwise the suppression is **rejected**, which can yield exit code **2**
(policy failure).

## Review workflow

1. Reproduce finding on synthetic or authorized config.
2. Confirm operational necessity and compensating controls.
3. Add suppression with owner + expiry + ticket.
4. Re-scan; confirm audit entry `applied`.
5. Calendar a review before `expires_at_utc`.

## Why suppressions remain visible

Risk acceptance must be reviewable. Reports include suppression audit entries
and mark findings as Suppressed rather than deleting them.
