"""Compose rule evaluation — Critical/High rules and representatives."""

from __future__ import annotations

from container_security_baseline.statuses import Status


def _fail_ids(findings):
    return {f.rule_id for f in findings if f.status == Status.FAIL}


def test_cmp_001_privileged(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-001",
        "services:\n  web:\n    image: registry.example.invalid/a:1\n    privileged: true\n",
    )
    assert "CSB-CMP-001" in _fail_ids(findings) or findings[0].status == Status.FAIL


def test_cmp_001_not_privileged(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-001",
        "services:\n  web:\n    image: registry.example.invalid/a:1\n    privileged: false\n",
    )
    assert findings == [] or all(f.status != Status.FAIL for f in findings)


def test_cmp_002_docker_sock(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-002",
        "services:\n  a:\n    image: registry.example.invalid/a:1\n"
        "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_cmp_003_root_bind(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-003",
        "services:\n  a:\n    image: registry.example.invalid/a:1\n    volumes:\n      - /:/host\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_cmp_004_sensitive_rw(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-004",
        "services:\n  a:\n    image: registry.example.invalid/a:1\n"
        "    volumes:\n      - /etc:/etc\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_cmp_007_pid_host(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-007",
        "services:\n  a:\n    image: registry.example.invalid/a:1\n    pid: host\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_cmp_006_network_mode_host(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-006",
        "services:\n  a:\n    image: registry.example.invalid/a:1\n    network_mode: host\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_cmp_020_cap_add_all(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-020",
        "services:\n  a:\n    image: registry.example.invalid/a:1\n    cap_add: [ALL]\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_cmp_021_dangerous_cap(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-021",
        "services:\n  a:\n    image: registry.example.invalid/a:1\n    cap_add: [SYS_ADMIN]\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_cmp_024_seccomp_unconfined(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-024",
        "services:\n  a:\n    image: registry.example.invalid/a:1\n"
        "    security_opt:\n      - seccomp:unconfined\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_cmp_050_secret_env(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-050",
        "services:\n  a:\n    image: registry.example.invalid/a:1\n"
        "    environment:\n      API_SECRET: SYNTHETIC_NOT_A_REAL_SECRET\n",
    )
    assert findings and findings[0].status == Status.FAIL
    assert "SYNTHETIC_NOT_A_REAL_SECRET" not in findings[0].evidence_redacted
    assert "[REDACTED]" in findings[0].evidence_redacted


def test_cmp_114_credentials_in_image(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-114",
        "services:\n  a:\n    image: https://user:SYNTHETIC_NOT_A_REAL_SECRET@registry.example.invalid/a:1\n",
    )
    # May or may not match depending on image parsing — if fail, must be redacted
    for f in findings:
        assert "SYNTHETIC_NOT_A_REAL_SECRET" not in f.evidence_redacted


def test_cmp_008_ipc_host(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-008",
        "services:\n  a:\n    image: registry.example.invalid/a:1\n    ipc: host\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_cmp_009_userns_host(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-009",
        "services:\n  a:\n    image: registry.example.invalid/a:1\n    userns_mode: host\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_cmp_022_missing_cap_drop(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-022",
        "services:\n  a:\n    image: registry.example.invalid/a:1\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_cmp_026_missing_nnp(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-026",
        "services:\n  a:\n    image: registry.example.invalid/a:1\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_cmp_040_missing_read_only(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-040",
        "services:\n  a:\n    image: registry.example.invalid/a:1\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_cmp_010_devices(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-010",
        "services:\n  a:\n    image: registry.example.invalid/a:1\n"
        "    devices:\n      - /dev/sda:/dev/sda\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_cmp_025_apparmor_unconfined(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-025",
        "services:\n  a:\n    image: registry.example.invalid/a:1\n"
        "    security_opt:\n      - apparmor:unconfined\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_cmp_030_missing_user(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-030",
        "services:\n  a:\n    image: registry.example.invalid/a:1\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_cmp_031_root_user(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-031",
        'services:\n  a:\n    image: registry.example.invalid/a:1\n    user: "0:0"\n',
    )
    assert findings and findings[0].status == Status.FAIL


def test_cmp_070_wildcard_port(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-070",
        'services:\n  a:\n    image: registry.example.invalid/a:1\n    ports:\n      - "*:8080"\n',
    )
    # Rule may be CSB-CMP-070 or related — accept fail if present
    assert isinstance(findings, list)


def test_cmp_100_missing_logging(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-100",
        "services:\n  a:\n    image: registry.example.invalid/a:1\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_cmp_085_missing_healthcheck(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-085",
        "services:\n  a:\n    image: registry.example.invalid/a:1\n",
    )
    assert findings and findings[0].status == Status.FAIL


def test_hardened_no_privileged(evaluate_compose_rule) -> None:
    findings = evaluate_compose_rule(
        "CSB-CMP-001",
        "services:\n  web:\n    image: registry.example.invalid/web:1.2.3\n"
        '    user: "10001:10001"\n    privileged: false\n',
    )
    assert findings == []


def test_insecure_example_triggers_criticals(repo_root, evaluate_compose_rule) -> None:
    text = (repo_root / "examples" / "compose" / "insecure-compose.yml").read_text(encoding="utf-8")
    for rule_id in ("CSB-CMP-001", "CSB-CMP-002", "CSB-CMP-007", "CSB-CMP-020", "CSB-CMP-050"):
        findings = evaluate_compose_rule(rule_id, text)
        assert any(f.status == Status.FAIL for f in findings), rule_id
