"""One test per v0.1 rule, plus loader behaviour (anchors, matrix, invalid YAML)."""

from __future__ import annotations

import pytest

from gha_portcheck.loader import WorkflowParseError
from gha_portcheck.scanner import scan_repo


def rule_ids(findings):
    return [f.rule for f in findings]


def by_rule(findings, rule_id):
    return [f for f in findings if f.rule == rule_id]


def scan(repo, target):
    findings, scanned = scan_repo(repo, target)
    return findings


# --- (a) runs-on ------------------------------------------------------------


@pytest.mark.parametrize("target", ["forgejo", "gitea"])
def test_runs_on_github_hosted_labels(make_repo, target):
    findings = scan(make_repo("a-runs-on.yml"), target)
    hits = by_rule(findings, "runs-on-github-hosted-label")
    assert [f.job for f in hits] == ["arm", "hosted", "mac"]
    assert {f.severity for f in hits} == {"warning"}
    assert "ubuntu-22.04-arm" in next(f.message for f in hits if f.job == "arm")
    # the self-hosted job is not reported at all
    assert all(f.job != "self" for f in findings)


def test_matrix_expanded_runs_on(make_repo):
    findings = scan(make_repo("matrix.yml"), "forgejo")
    hits = by_rule(findings, "runs-on-github-hosted-label")
    labels = sorted(f.message.split("'")[1] for f in hits)
    assert labels == ["ubuntu-latest", "windows-2022"]


def test_anchors_and_aliases_are_resolved(make_repo):
    findings = scan(make_repo("anchors.yml"), "gitea")
    hits = by_rule(findings, "runs-on-github-hosted-label")
    assert [f.job for f in hits] == ["one", "two"]


# --- (b) artifact actions ---------------------------------------------------


def test_artifact_v4_is_an_error_on_forgejo_only(make_repo):
    repo = make_repo("b-artifacts.yml")
    forgejo = by_rule(scan(repo, "forgejo"), "artifact-actions-v4")
    assert [f.step for f in forgejo] == [0, 1]
    assert {f.severity for f in forgejo} == {"error"}
    assert by_rule(scan(repo, "gitea"), "artifact-actions-v4") == []


def test_artifact_v4_actions_are_not_reported_as_unknown(make_repo):
    findings = scan(make_repo("b-artifacts.yml"), "forgejo")
    assert by_rule(findings, "unknown-action") == []


# --- (c) GitHub-only services -----------------------------------------------


@pytest.mark.parametrize("target", ["forgejo", "gitea"])
def test_github_only_services_are_errors(make_repo, target):
    findings = scan(make_repo("c-github-only.yml"), target)
    fired = {f.rule for f in findings}
    assert {"github-only-codeql", "github-only-attestations", "github-only-pages"} <= fired
    assert all(f.severity == "error" for f in findings if f.rule.startswith("github-only-"))
    assert by_rule(findings, "unknown-action") == []


# --- (d) OIDC ---------------------------------------------------------------


@pytest.mark.parametrize("target", ["forgejo", "gitea"])
def test_id_token_write_is_a_warning(make_repo, target):
    findings = scan(make_repo("d-oidc.yml"), target)
    hits = by_rule(findings, "oidc-id-token")
    assert [(f.job, f.severity) for f in hits] == [("deploy", "warning")]


# --- (e) job environment ----------------------------------------------------


def test_job_environment_is_a_warning_on_gitea_only(make_repo):
    repo = make_repo("e-environment.yml")
    gitea = by_rule(scan(repo, "gitea"), "job-environment")
    assert [(f.job, f.severity) for f in gitea] == [("deploy", "warning")]
    assert by_rule(scan(repo, "forgejo"), "job-environment") == []


# --- (f) labeled / unlabeled ------------------------------------------------


@pytest.mark.parametrize("target", ["forgejo", "gitea"])
def test_pull_request_labeled_types(make_repo, target):
    findings = scan(make_repo("f-pr-labeled.yml"), target)
    hits = by_rule(findings, "pull-request-labeled-types")
    assert len(hits) == 1
    assert hits[0].severity == "info"
    assert hits[0].job is None and hits[0].step is None
    assert "labeled" in hits[0].message and "unlabeled" in hits[0].message


# --- (g) container + JavaScript action --------------------------------------


@pytest.mark.parametrize("target", ["forgejo", "gitea"])
def test_container_with_js_action(make_repo, target):
    findings = scan(make_repo("g-container-js.yml"), target)
    hits = by_rule(findings, "container-js-action-node")
    assert [(f.job, f.step) for f in hits] == [("build", 0)]
    assert hits[0].severity == "warning"
    assert "node" in hits[0].message


def test_js_action_without_container_is_not_flagged(make_repo):
    findings = scan(make_repo("b-artifacts.yml"), "forgejo")
    assert by_rule(findings, "container-js-action-node") == []


# --- (h) GitHub API / gh CLI in run steps -----------------------------------


@pytest.mark.parametrize("target", ["forgejo", "gitea"])
def test_github_api_in_run_steps(make_repo, target):
    findings = scan(make_repo("h-gh-api.yml"), target)
    hits = by_rule(findings, "github-api-in-run")
    assert [f.step for f in hits] == [0, 1]
    assert {f.severity for f in hits} == {"warning"}


def test_plain_run_steps_are_not_flagged(make_repo):
    findings = scan(make_repo("clean.yml"), "forgejo")
    assert by_rule(findings, "github-api-in-run") == []


# --- unknown actions / clean workflow ---------------------------------------


def test_clean_workflow_only_reports_unknown_actions(make_repo):
    findings = scan(make_repo("clean.yml"), "forgejo")
    assert rule_ids(findings) == ["unknown-action"]
    assert findings[0].severity == "info"
    assert "some-org/some-action" in findings[0].message
    assert findings[0].step == 1


def test_unknown_action_reported_once_per_action(make_repo, tmp_path):
    repo = make_repo("clean.yml")
    second = repo / ".github/workflows/clean2.yml"
    second.write_text((repo / ".github/workflows/clean.yml").read_text())
    findings = scan(repo, "forgejo")
    assert rule_ids(findings) == ["unknown-action"]


# --- workflow discovery -----------------------------------------------------


@pytest.mark.parametrize("directory", [".forgejo/workflows", ".gitea/workflows"])
def test_forge_native_workflow_directories_are_scanned(make_repo, directory):
    repo = make_repo("a-runs-on.yml", directory=directory)
    findings = scan(repo, "forgejo")
    assert findings
    assert findings[0].file.startswith(directory)


def test_findings_are_sorted(make_repo):
    repo = make_repo("a-runs-on.yml", "b-artifacts.yml", "h-gh-api.yml")
    findings = scan(repo, "forgejo")
    keys = [(f.file, f.job or "", -1 if f.step is None else f.step, f.rule) for f in findings]
    assert keys == sorted(keys)


def test_yaml_and_yml_suffixes(make_repo):
    repo = make_repo("clean.yml")
    (repo / ".github/workflows/other.yaml").write_text(
        "on: [push]\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n"
    )
    findings = scan(repo, "forgejo")
    assert any(f.file.endswith("other.yaml") for f in findings)


# --- invalid YAML -----------------------------------------------------------


def test_invalid_yaml_raises_with_line(make_repo):
    repo = make_repo("invalid.yml")
    with pytest.raises(WorkflowParseError) as excinfo:
        scan_repo(repo, "forgejo")
    assert excinfo.value.path == ".github/workflows/invalid.yml"
    assert excinfo.value.line == 6


def test_repo_without_workflows(tmp_path):
    findings, scanned = scan_repo(tmp_path, "forgejo")
    assert findings == [] and scanned == []
