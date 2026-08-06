# Compose trust model

## Summary

Compose input must be **trusted for analysis** before findings are treated as
actionable for a deployment decision. This tool performs **offline static
analysis** only. It never executes Compose and never talks to a container
engine.

## What the analyzer does not do

| Behavior | Status |
|----------|--------|
| Execute `docker compose` / `podman-compose` | Never |
| Resolve `${VAR}` / default interpolation | Detected, not resolved |
| Follow `include` | Flagged; not followed |
| Follow `extends` / `extends.file` | Flagged; not followed |
| Read `env_file` bodies | Not read |
| Read `secrets:` / `configs:` file sources | Not read |
| Pull images or resolve digests | Never |
| Merge override files automatically | Only explicit CLI inputs |

## Implications

1. **Literal analysis:** Findings reflect what appears in the supplied file(s),
   not the fully evaluated Compose model Docker would build at runtime.
2. **Referenced content:** A secret stored only in an external env file will
   not be inspected. The presence of an `env_file` reference may still produce
   a Medium finding (`CSB-CMP-055`) as **potential exposure** / trust signal.
3. **Pre-resolved JSON:** Operators may supply Compose JSON via
   `--compose-json`. That document may already contain expanded sensitive
   values — treat it as highly sensitive and prefer `--privacy-mode masked`.
4. **Anchors and merge keys:** YAML anchors/aliases may hide sensitive reuse
   (`CSB-CMP-138`, `CSB-CMP-139`). Patch generation refuses documents with
   anchors/merge keys.
5. **Effective runtime config:** Separately review the configuration that will
   actually run (orchestrator overlays, swarm secrets, CI variable injection,
   host mounts). Static analysis cannot reproduce every Compose evaluation
   aspect.

## Operator checklist

- [ ] Inputs are intentional review artifacts (not accidental production dumps)
- [ ] Interpolation sources are reviewed outside this tool
- [ ] include/extends trees are reviewed as separate inputs if needed
- [ ] Findings marked potential exposure receive human review
- [ ] Score/grade are treated as prioritization aids, not certification

See also [compose-analysis.md](compose-analysis.md) and
[input-safety.md](input-safety.md).
