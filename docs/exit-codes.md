# Exit codes

Defined in `exit_codes.py` and computed in `evaluator._compute_exit_code`.

| Code | Name | Meaning |
|-----:|------|---------|
| **0** | SUCCESS | No unsuppressed Fail/Warning findings, or only Informational; policy thresholds satisfied |
| **1** | FINDINGS_BELOW | Unsuppressed findings exist but all are **below** `fail_on`, and score ≥ `minimum_score` |
| **2** | POLICY_FAILURE | Unsuppressed findings at/above `fail_on`, score below `minimum_score`, or Critical suppression policy rejection |
| **3** | ERROR | Invalid input, parse failure, unsafe path, config/policy/suppression load error, or internal error |

## Policy failure details

Exit **2** when any of the following hold:

- An unsuppressed Fail/Warning finding has severity ≥ policy/CLI `fail_on`
- Numeric score is below `minimum_score`
- A Critical suppression was rejected under policy controls

## Error vs expected insecure fixtures

Scanning `examples/compose/insecure-compose.yml` under baseline/strict often
returns **2** because it intentionally contains High/Critical findings. That
is an **expected policy failure**, not an application crash.

Exit **3** indicates the tool could not complete analysis safely or correctly.

## Automation tips

```bash
container-security-baseline scan ... ; echo $?
```

Gate merges on `0` (clean) or allow `1` if your process accepts below-threshold
noise. Treat `2` as a failing security gate unless reviewing known-bad fixtures.
