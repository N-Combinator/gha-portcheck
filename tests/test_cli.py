from __future__ import annotations

import json

import pytest

from gha_portcheck.cli import main


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_scan_json_output_shape(make_repo, capsys):
    repo = make_repo("a-runs-on.yml")
    code, out, err = run(capsys, "scan", str(repo), "--target", "forgejo")
    assert code == 0
    findings = json.loads(out)
    assert findings
    for finding in findings:
        assert set(finding) == {
            "file",
            "job",
            "step",
            "rule",
            "severity",
            "message",
            "fix_hint",
            "source_url",
        }
        assert finding["severity"] in ("error", "warning", "info")
        assert finding["source_url"].startswith("https://")


def test_scan_markdown_output(make_repo, capsys):
    repo = make_repo("b-artifacts.yml")
    code, out, err = run(capsys, "scan", str(repo), "--target", "forgejo", "--format", "markdown")
    assert code == 0
    assert out.startswith("# gha-portcheck: forgejo")
    assert "| artifact-actions-v4 |" in out
    assert out.count("\n|") >= 3


def test_fail_on_error(make_repo, capsys):
    repo = make_repo("b-artifacts.yml")  # error on forgejo, nothing on gitea
    assert run(capsys, "scan", str(repo), "--target", "forgejo", "--fail-on", "error")[0] == 1
    assert run(capsys, "scan", str(repo), "--target", "gitea", "--fail-on", "error")[0] == 0


def test_fail_on_warning(make_repo, capsys):
    repo = make_repo("a-runs-on.yml")  # warnings only
    assert run(capsys, "scan", str(repo), "--target", "forgejo", "--fail-on", "warning")[0] == 1
    assert run(capsys, "scan", str(repo), "--target", "forgejo", "--fail-on", "error")[0] == 0


def test_fail_on_ignores_info(make_repo, capsys):
    repo = make_repo("clean.yml")  # unknown-action info only
    assert run(capsys, "scan", str(repo), "--target", "forgejo", "--fail-on", "warning")[0] == 0


def test_no_fail_on_always_exits_zero(make_repo, capsys):
    repo = make_repo("c-github-only.yml")
    assert run(capsys, "scan", str(repo), "--target", "forgejo")[0] == 0


def test_invalid_yaml_exits_2_with_path_and_line(make_repo, capsys):
    repo = make_repo("invalid.yml")
    code, out, err = run(capsys, "scan", str(repo), "--target", "forgejo")
    assert code == 2
    assert ".github/workflows/invalid.yml:6" in err
    assert out == ""


def test_non_utf8_workflow_exits_2(make_repo, capsys):
    repo = make_repo()
    (repo / ".github/workflows/latin1.yml").write_bytes("on: [push] # caf\xe9\n".encode("latin-1"))
    code, out, err = run(capsys, "scan", str(repo), "--target", "forgejo")
    assert code == 2
    assert ".github/workflows/latin1.yml: not valid UTF-8" in err
    assert out == ""


def test_repo_without_workflows(tmp_path, capsys):
    code, out, err = run(capsys, "scan", str(tmp_path), "--target", "gitea")
    assert code == 0
    assert json.loads(out) == []
    assert "no workflow files found" in err


def test_missing_repo_directory(tmp_path, capsys):
    code, out, err = run(capsys, "scan", str(tmp_path / "nope"), "--target", "gitea")
    assert code == 2
    assert "not a directory" in err


def test_rules_listing(capsys):
    code, out, err = run(capsys, "rules")
    assert code == 0
    ids = [line.split()[0] for line in out.strip().splitlines()]
    assert "unknown-action" in ids
    assert "runs-on-github-hosted-label" in ids
    assert len(ids) == len(set(ids))


def test_rules_explain(capsys):
    code, out, err = run(capsys, "rules", "--explain", "artifact-actions-v4")
    assert code == 0
    assert "artifact-actions-v4" in out
    assert "https://" in out
    assert "forgejo" in out


def test_rules_explain_json(capsys):
    code, out, err = run(capsys, "rules", "--explain", "job-environment", "--format", "json")
    assert code == 0
    rule = json.loads(out)
    assert rule["id"] == "job-environment"
    assert rule["targets"] == ["gitea"]


def test_rules_explain_unknown_id(capsys):
    code, out, err = run(capsys, "rules", "--explain", "no-such-rule")
    assert code == 2
    assert "unknown rule" in err


def test_target_is_required(make_repo, capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["scan", str(make_repo("clean.yml"))])
    assert excinfo.value.code == 2


def test_markdown_output_without_findings(tmp_path, capsys):
    code, out, err = run(capsys, "scan", str(tmp_path), "--target", "forgejo", "--format", "markdown")
    assert code == 0
    assert "No findings." in out


def test_workflow_level_permissions_are_checked(make_repo, tmp_path, capsys):
    repo = make_repo()
    (repo / ".github/workflows/w.yml").write_text(
        "on: [push]\npermissions:\n  id-token: write\njobs:\n"
        "  j:\n    runs-on: self-hosted\n    steps:\n      - run: true\n"
    )
    code, out, err = run(capsys, "scan", str(repo), "--target", "gitea")
    findings = json.loads(out)
    assert [(f["rule"], f["job"], f["step"]) for f in findings] == [("oidc-id-token", None, None)]
