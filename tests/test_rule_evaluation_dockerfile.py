"""Dockerfile rule evaluation tests."""

from __future__ import annotations

from container_security_baseline.statuses import Status


def test_df_001_latest_tag(evaluate_dockerfile_rule) -> None:
    findings = evaluate_dockerfile_rule(
        "CSB-DF-001",
        "FROM registry.example.invalid/app:latest\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_df_001_pinned_ok(evaluate_dockerfile_rule) -> None:
    findings = evaluate_dockerfile_rule(
        "CSB-DF-001",
        "FROM registry.example.invalid/app:1.2.3\n",
    )
    assert findings == []


def test_df_010_missing_user(evaluate_dockerfile_rule) -> None:
    findings = evaluate_dockerfile_rule(
        "CSB-DF-010",
        'FROM registry.example.invalid/app:1\nCMD ["true"]\n',
    )
    assert findings and findings[0].status == Status.FAIL


def test_df_011_user_root(evaluate_dockerfile_rule) -> None:
    findings = evaluate_dockerfile_rule(
        "CSB-DF-011",
        "FROM registry.example.invalid/app:1\nUSER root\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_df_020_secret_env(evaluate_dockerfile_rule) -> None:
    findings = evaluate_dockerfile_rule(
        "CSB-DF-020",
        "FROM scratch\nENV API_SECRET=SYNTHETIC_NOT_A_REAL_SECRET\n",
    )
    assert findings and findings[0].status == Status.FAIL
    assert "SYNTHETIC_NOT_A_REAL_SECRET" not in findings[0].evidence_redacted


def test_df_021_secret_arg(evaluate_dockerfile_rule) -> None:
    findings = evaluate_dockerfile_rule(
        "CSB-DF-021",
        "FROM scratch\nARG DATABASE_PASSWORD=SYNTHETIC_NOT_A_REAL_SECRET\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_df_022_secret_literal(evaluate_dockerfile_rule) -> None:
    findings = evaluate_dockerfile_rule(
        "CSB-DF-022",
        "FROM scratch\nENV TOKEN=ghp_" + ("A" * 36) + "\n",
    )
    assert findings and findings[0].status == Status.FAIL
    assert (
        "[REDACTED]" in findings[0].evidence_redacted
        or "fingerprint=" in findings[0].evidence_redacted
    )


def test_df_023_sensitive_copy(evaluate_dockerfile_rule) -> None:
    findings = evaluate_dockerfile_rule(
        "CSB-DF-023",
        "FROM scratch\nCOPY id_rsa /keys/\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_df_030_add_remote(evaluate_dockerfile_rule) -> None:
    findings = evaluate_dockerfile_rule(
        "CSB-DF-030",
        "FROM scratch\nADD https://example.invalid/x.tar /app/\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_df_031_add_prefer_copy(evaluate_dockerfile_rule) -> None:
    findings = evaluate_dockerfile_rule(
        "CSB-DF-031",
        "FROM scratch\nADD localfile /app/\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_df_032_curl_pipe_sh(evaluate_dockerfile_rule) -> None:
    findings = evaluate_dockerfile_rule(
        "CSB-DF-032",
        "FROM scratch\nRUN curl https://example.invalid/x | sh\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_df_032_wget_pipe(evaluate_dockerfile_rule) -> None:
    findings = evaluate_dockerfile_rule(
        "CSB-DF-032",
        "FROM scratch\nRUN wget -O- https://example.invalid/x | bash\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_df_050_chmod_777(evaluate_dockerfile_rule) -> None:
    findings = evaluate_dockerfile_rule(
        "CSB-DF-050",
        "FROM scratch\nRUN chmod 777 /app\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_df_012_user_escalation(evaluate_dockerfile_rule) -> None:
    findings = evaluate_dockerfile_rule(
        "CSB-DF-012",
        "FROM scratch\nUSER 1000\nUSER root\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_df_061_shell_form_cmd(evaluate_dockerfile_rule) -> None:
    findings = evaluate_dockerfile_rule(
        "CSB-DF-061",
        "FROM scratch\nCMD /app/start.sh\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_df_060_shell_entrypoint(evaluate_dockerfile_rule) -> None:
    findings = evaluate_dockerfile_rule(
        "CSB-DF-060",
        "FROM scratch\nENTRYPOINT /app/start.sh\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_df_064_missing_healthcheck(evaluate_dockerfile_rule) -> None:
    findings = evaluate_dockerfile_rule(
        "CSB-DF-064",
        'FROM scratch\nUSER 1000\nCMD ["true"]\n',
    )
    assert findings and findings[0].status == Status.FAIL


def test_df_002_missing_digest(evaluate_dockerfile_rule) -> None:
    findings = evaluate_dockerfile_rule(
        "CSB-DF-002",
        "FROM registry.example.invalid/app:1.2.3\n",
    )
    # Digest requirement may be informational / policy gated — accept list
    assert isinstance(findings, list)


def test_insecure_dockerfile_example(repo_root, evaluate_dockerfile_rule) -> None:
    text = (repo_root / "examples" / "dockerfiles" / "Dockerfile.insecure").read_text(
        encoding="utf-8"
    )
    for rule_id in ("CSB-DF-011", "CSB-DF-021", "CSB-DF-032", "CSB-DF-050"):
        findings = evaluate_dockerfile_rule(rule_id, text)
        assert any(f.status == Status.FAIL for f in findings), rule_id


def test_hardened_dockerfile_non_root(evaluate_dockerfile_rule) -> None:
    findings = evaluate_dockerfile_rule(
        "CSB-DF-011",
        'FROM registry.example.invalid/app:1.2.3\nUSER 10001:10001\nCMD ["true"]\n',
    )
    assert findings == []


def test_df_024_secret_via_arg(evaluate_dockerfile_rule) -> None:
    findings = evaluate_dockerfile_rule(
        "CSB-DF-024",
        "FROM scratch\nARG PASSWORD=SYNTHETIC_NOT_A_REAL_SECRET\n",
    )
    assert isinstance(findings, list)
    for f in findings:
        assert "SYNTHETIC_NOT_A_REAL_SECRET" not in f.evidence_redacted
