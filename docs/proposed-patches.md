# Proposed patches

## Summary

The `suggest` command may emit a **proposed** unified diff for selected Compose
YAML findings. Patches are **never auto-applied** to input files.

Header included in outputs:

```text
PROPOSED REMEDIATION ONLY — MANUAL REVIEW REQUIRED
```

## Conservative changes

Only rules marked `patchability: safe` and listed in `SAFE_PATCHABLE_RULES`
are candidates (for example privileged false, selected capability/read-only
hygiene). Most rules remain **manual**.

## Refusal conditions

Patch generation refuses (among other cases):

- Non-YAML / canonical JSON inputs
- YAML anchors or merge keys
- Compose `include` or `extends`
- Custom YAML tags
- Secret-like tokens near the edit window (`secrets nearby`)
- Ambiguous service/line matching

Refusal reasons are returned so operators know why no diff was produced.

## YAML-anchor limitations

Anchors/aliases can duplicate sensitive values and make line-oriented edits
unsafe. Documents with anchors are refused rather than partially rewritten.

## Manual testing and deployment validation

1. Review the diff carefully.
2. Apply manually in a branch if appropriate.
3. Re-scan and run application tests.
4. Deploy to a non-production environment before production.

## Safety guarantees

- Analyzer never writes over `--compose` inputs.
- Output path is chosen by `--output` (default `proposed-remediation.patch`).
- Presence of a patch does not mean the change is safe for your workload.
