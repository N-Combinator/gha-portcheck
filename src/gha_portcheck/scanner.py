"""Static portability checks over parsed workflows."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from . import rules as rules_mod
from .loader import Workflow, discover, load, relpath

# ``on:`` is parsed as the boolean ``True`` by PyYAML (YAML 1.1), so both keys
# have to be looked up.
ON_KEYS = ("on", True)

GITHUB_HOSTED_LABEL_RE = re.compile(r"^(ubuntu|macos|windows)-|-arm$", re.IGNORECASE)
MATRIX_REF_RE = re.compile(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}")
GH_CLI_RE = re.compile(r"(?:^|[\s;&|(`$])gh\s+[a-z]", re.MULTILINE)

ARTIFACT_V4_RE = re.compile(r"^actions/(upload|download)-artifact@v4(\.|$)", re.IGNORECASE)

# action reference prefix -> rule id, for actions backed by a GitHub-only service
GITHUB_ONLY_ACTIONS = (
    ("github/codeql-action", "github-only-codeql"),
    ("actions/attest-build-provenance", "github-only-attestations"),
    ("actions/attest", "github-only-attestations"),
    ("actions/deploy-pages", "github-only-pages"),
    ("actions/upload-pages-artifact", "github-only-pages"),
    ("actions/configure-pages", "github-only-pages"),
)

# actions/* are JavaScript actions: inside a job container they need node in the image
JS_ACTION_PREFIX = "actions/"


@dataclass(frozen=True)
class Finding:
    file: str
    job: str | None
    step: int | None
    rule: str
    severity: str
    message: str
    fix_hint: str
    source_url: str

    def as_dict(self) -> dict:
        return {
            "file": self.file,
            "job": self.job,
            "step": self.step,
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "fix_hint": self.fix_hint,
            "source_url": self.source_url,
        }

    def sort_key(self) -> tuple:
        return (self.file, self.job or "", -1 if self.step is None else self.step, self.rule)


class _Emitter:
    """Turns (rule id, location, message arguments) into findings for one target."""

    def __init__(self, target: str) -> None:
        self.target = target
        self.catalogue = rules_mod.load_rules()
        self.findings: list[Finding] = []

    def emit(
        self,
        rule_id: str,
        file: str,
        job: str | None = None,
        step: int | None = None,
        **fmt: object,
    ) -> None:
        rule = self.catalogue[rule_id]
        if not rule.applies_to(self.target):
            return
        self.findings.append(
            Finding(
                file=file,
                job=job,
                step=step,
                rule=rule.id,
                severity=rule.severity,
                message=rule.message.format(**fmt) if fmt else rule.message,
                fix_hint=rule.fix_hint,
                source_url=rule.source_url,
            )
        )


def scan_repo(repo: Path, target: str) -> tuple[list[Finding], list[str]]:
    """Scan every workflow file below ``repo``.

    Returns the sorted findings and the list of scanned workflow paths. Raises
    :class:`~gha_portcheck.loader.WorkflowParseError` on invalid YAML.
    """
    paths = discover(repo)
    workflows = [load(path, relpath(path, repo)) for path in paths]
    return scan_workflows(workflows, target), [wf.path for wf in workflows]


def scan_workflows(workflows: list[Workflow], target: str) -> list[Finding]:
    emitter = _Emitter(target)
    seen_unknown: set[str] = set()
    for workflow in workflows:
        _scan_workflow(workflow, emitter, seen_unknown)
    return sorted(emitter.findings, key=Finding.sort_key)


def _scan_workflow(workflow: Workflow, emitter: _Emitter, seen_unknown: set[str]) -> None:
    data = workflow.data
    file = workflow.path

    _check_pull_request_types(data, file, emitter)
    _check_permissions(_mapping(data.get("permissions")), file, None, emitter)

    jobs = _mapping(data.get("jobs"))
    for job_id, job in jobs.items():
        job_name = str(job_id)
        job = _mapping(job)
        _check_permissions(_mapping(job.get("permissions")), file, job_name, emitter)
        _check_runs_on(job, file, job_name, emitter)
        _check_environment(job, file, job_name, emitter)

        in_container = bool(job.get("container"))
        job_uses = job.get("uses")
        if isinstance(job_uses, str):
            _check_uses(job_uses, file, job_name, None, False, emitter, seen_unknown)

        steps = job.get("steps")
        if not isinstance(steps, list):
            continue
        for index, step in enumerate(steps):
            step = _mapping(step)
            uses = step.get("uses")
            if isinstance(uses, str):
                _check_uses(uses, file, job_name, index, in_container, emitter, seen_unknown)
            run = step.get("run")
            if isinstance(run, str):
                _check_run(run, file, job_name, index, emitter)


# --- individual checks -------------------------------------------------------


def _check_pull_request_types(data: dict, file: str, emitter: _Emitter) -> None:
    on = None
    for key in ON_KEYS:
        if key in data:
            on = data[key]
            break
    if not isinstance(on, dict):
        return
    pull_request = _mapping(on.get("pull_request"))
    types = pull_request.get("types")
    if isinstance(types, str):
        types = [types]
    if not isinstance(types, list):
        return
    hits = [t for t in types if t in ("labeled", "unlabeled")]
    if hits:
        emitter.emit(
            "pull-request-labeled-types",
            file,
            types=", ".join(sorted(set(hits))),
        )


def _check_permissions(permissions: dict, file: str, job: str | None, emitter: _Emitter) -> None:
    if permissions.get("id-token") == "write":
        emitter.emit("oidc-id-token", file, job=job)


def _check_environment(job: dict, file: str, job_name: str, emitter: _Emitter) -> None:
    if job.get("environment") is not None:
        emitter.emit("job-environment", file, job=job_name)


def _check_runs_on(job: dict, file: str, job_name: str, emitter: _Emitter) -> None:
    matrix = _mapping(_mapping(job.get("strategy")).get("matrix"))
    labels: list[str] = []
    for value in _as_list(job.get("runs-on")):
        labels.extend(_resolve_labels(value, matrix))
    reported: set[str] = set()
    for label in labels:
        if GITHUB_HOSTED_LABEL_RE.search(label) and label not in reported:
            reported.add(label)
            emitter.emit("runs-on-github-hosted-label", file, job=job_name, label=label)


def _resolve_labels(value: object, matrix: dict) -> list[str]:
    """Expand a ``runs-on`` entry, following ``matrix`` references."""
    if isinstance(value, dict):  # runs-on: {group: ..., labels: [...]}
        return [v for item in _as_list(value.get("labels")) for v in _resolve_labels(item, matrix)]
    if not isinstance(value, str):
        return []
    refs = MATRIX_REF_RE.findall(value)
    if not refs:
        return [value]
    resolved: list[str] = []
    for key in refs:
        resolved.extend(_matrix_values(matrix, key))
    return resolved


def _matrix_values(matrix: dict, key: str) -> list[str]:
    values: list[str] = []
    direct = matrix.get(key)
    if isinstance(direct, list):
        values.extend(str(v) for v in direct if isinstance(v, (str, int, float)))
    include = matrix.get("include")
    if isinstance(include, list):
        for entry in include:
            entry = _mapping(entry)
            if key in entry and isinstance(entry[key], str):
                values.append(entry[key])
    return values


def _check_uses(
    uses: str,
    file: str,
    job: str,
    step: int | None,
    in_container: bool,
    emitter: _Emitter,
    seen_unknown: set[str],
) -> None:
    ref = uses.strip()
    if ref.startswith("./") or ref.startswith("../"):
        return
    action = ref.split("@", 1)[0]

    covered = False
    if ARTIFACT_V4_RE.match(ref):
        covered = True
        emitter.emit("artifact-actions-v4", file, job=job, step=step, uses=ref)
    for prefix, rule_id in GITHUB_ONLY_ACTIONS:
        if action == prefix or action.startswith(prefix + "/"):
            covered = True
            emitter.emit(rule_id, file, job=job, step=step, uses=ref)
            break

    if in_container and action.startswith(JS_ACTION_PREFIX):
        emitter.emit("container-js-action-node", file, job=job, step=step, uses=ref)

    if not covered and action not in seen_unknown:
        seen_unknown.add(action)
        emitter.emit("unknown-action", file, job=job, step=step, action=action)


def _check_run(run: str, file: str, job: str, step: int, emitter: _Emitter) -> None:
    if "api.github.com" in run:
        emitter.emit("github-api-in-run", file, job=job, step=step, what="api.github.com")
    elif GH_CLI_RE.search(run):
        emitter.emit("github-api-in-run", file, job=job, step=step, what="the gh CLI")


# --- helpers -----------------------------------------------------------------


def _mapping(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _as_list(value: object) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]
