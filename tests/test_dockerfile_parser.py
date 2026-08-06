"""Tests for conservative Dockerfile parser."""

from __future__ import annotations

from container_security_baseline.dockerfile_parser import (
    ParseStatus,
    final_user,
    parse_dockerfile,
    stage_users,
)


def test_parse_basic_stages() -> None:
    doc = parse_dockerfile(
        "# SYNTHETIC\nFROM registry.example.invalid/a:1 AS build\nRUN echo hi\n"
        "FROM registry.example.invalid/a:1 AS final\nUSER 1000\n"
    )
    assert len(doc.stages) == 2
    assert doc.final_stage is not None
    assert doc.final_stage.name == "final"
    assert final_user(doc) == "1000"


def test_line_continuation() -> None:
    doc = parse_dockerfile("FROM registry.example.invalid/a:1\nRUN echo one && \\\n    echo two\n")
    runs = [i for i in doc.instructions if i.name == "RUN"]
    assert len(runs) == 1
    assert "echo two" in runs[0].args_raw
    assert runs[0].line_start < runs[0].line_end or runs[0].line_end == runs[0].line_start + 1


def test_json_cmd_form() -> None:
    doc = parse_dockerfile('FROM scratch\nCMD ["python", "-m", "app"]\n')
    cmds = [i for i in doc.instructions if i.name == "CMD"]
    assert cmds[0].is_json_form is True
    assert cmds[0].json_value == ["python", "-m", "app"]


def test_env_key_value() -> None:
    doc = parse_dockerfile("FROM scratch\nENV FOO=bar BAZ=qux\n")
    assert any(i.name == "ENV" for i in doc.instructions)


def test_copy_flags() -> None:
    doc = parse_dockerfile(
        "FROM registry.example.invalid/a:1\nCOPY --chown=1:1 --from=build /a /b\n"
    )
    copies = [i for i in doc.instructions if i.name == "COPY"]
    assert "chown" in copies[0].flags
    assert "from" in copies[0].flags


def test_unrecognized_instruction_partial() -> None:
    doc = parse_dockerfile("FROM scratch\nFOOBAR something\n")
    assert doc.status == ParseStatus.PARTIAL
    assert any("Unrecognized" in w for w in doc.warnings)


def test_parser_directive() -> None:
    doc = parse_dockerfile("# syntax=docker/dockerfile:1\nFROM scratch\n")
    assert "syntax" in doc.parser_directives


def test_complex_shell_marked_partial() -> None:
    doc = parse_dockerfile("FROM scratch\nRUN echo $(whoami)\n")
    assert doc.status == ParseStatus.PARTIAL
    runs = [i for i in doc.instructions if i.name == "RUN"]
    assert runs[0].partial is True


def test_stage_users() -> None:
    doc = parse_dockerfile("FROM scratch AS x\nUSER root\nUSER 1000\n")
    users = stage_users(doc.stages[0])
    assert len(users) == 2
    assert users[-1][1] == "1000"


def test_onbuild_wrapper() -> None:
    doc = parse_dockerfile("FROM scratch\nONBUILD RUN echo hi\n")
    assert any("ONBUILD" in n for i in doc.instructions for n in i.notes) or any(
        i.name == "RUN" for i in doc.instructions
    )


def test_healthcheck_none() -> None:
    doc = parse_dockerfile("FROM scratch\nHEALTHCHECK NONE\n")
    hc = [i for i in doc.instructions if i.name == "HEALTHCHECK"]
    assert hc
    assert "NONE" in hc[0].args_raw.upper()


def test_empty_dockerfile() -> None:
    doc = parse_dockerfile("")
    assert doc.stages == []
    assert doc.status == ParseStatus.OK
