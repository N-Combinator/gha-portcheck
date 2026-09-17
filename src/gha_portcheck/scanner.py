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
# ``uses:`` may be written as an absolute URL on any forge; the scheme and the
# host are split off so that a rule can decide whether it cares about the host.
USES_SCHEME_RE = re.compile(r"^https?://", re.IGNORECASE)
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9.-]+(?::\d+)?$")
GITHUB_HOST = "github.com"

# a matrix reference expands to at most this many labels, and nested references
# are followed at most this deep, so that a self-referencing matrix terminates
MAX_MATRIX_LABELS = 64
MAX_MATRIX_DEPTH = 8
# ``gh`` as a whole word followed by an argument on the same line: anything that
# is not a word character, ``.``, ``/`` or ``-`` may precede it (start of string,
# a shell separator, a quote in ``bash -c "gh api ..."``, an assignment prefix in
# ``GH_TOKEN=x gh auth status``), and the argument may be a flag, an upper-case
# word or a variable.  The excluded prefixes keep ``high``, ``weight``, ``./gh``
# and ``dir/gh`` out; requiring a space or tab right after keeps ``ghcr.io`` and
# ``gh-pages`` out.  The separators stay on one line, hence [ \t] rather than \s.
GH_CLI_RE = re.compile(r"(?<![\w./-])gh[ \t]+\S")

ARTIFACT_V4_RE = re.compile(r"^actions/(upload|download)-artifact@v4(\.|$)", re.IGNORECASE)

# action reference -> rule id, for actions backed by a GitHub-only service.  A
# pattern ending in ``*`` matches every repository whose name starts with it
# (``actions/attest``, ``actions/attest-build-provenance``, ``actions/attest-sbom``);
# without it the pattern matches the action itself and the sub-path actions in the
# same repository (``github/codeql-action/init``).
GITHUB_ONLY_ACTIONS = (
    ("github/codeql-action", "github-only-codeql"),
    ("actions/attest*", "github-only-attestations"),
    ("actions/deploy-pages", "github-only-pages"),
    ("actions/upload-pages-artifact", "github-only-pages"),
    ("actions/configure-pages", "github-only-pages"),
)

# actions/* are JavaScript actions: inside a job container they need node in the
# image. The owner decides, not the host: Forgejo and Gitea mirror these actions
# (code.forgejo.org/actions/checkout, gitea.com/actions/checkout) unchanged.
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
    ) -> bool:
        """Record a finding; return whether the rule applies to this target."""
        rule = self.catalogue[rule_id]
        if not rule.applies_to(self.target):
            return False
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
        return True


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
    return _expand_matrix_refs(value, matrix)


def _expand_matrix_refs(value: str, matrix: dict, depth: int = 0) -> list[str]:
    """Substitute every ``${{ matrix.X }}`` reference in ``value``.

    The reference may be the whole string (``${{ matrix.os }}``) or part of one
    (``ubuntu-${{ matrix.version }}``). A reference the matrix does not define is
    left as written, so the literal part of the label is still matched.
    """
    match = MATRIX_REF_RE.search(value)
    if match is None or depth >= MAX_MATRIX_DEPTH:
        return [value]
    candidates = _matrix_values(matrix, match.group(1))
    if not candidates:
        return [value]
    expanded: list[str] = []
    for candidate in candidates:
        substituted = value[: match.start()] + candidate + value[match.end() :]
        for label in _expand_matrix_refs(substituted, matrix, depth + 1):
            if label not in expanded:
                expanded.append(label)
            if len(expanded) >= MAX_MATRIX_LABELS:
                return expanded
    return expanded


def _matrix_values(matrix: dict, key: str) -> list[str]:
    values: list[str] = []
    direct = matrix.get(key)
    if isinstance(direct, list):
        values.extend(str(v) for v in direct if isinstance(v, (str, int, float)))
    include = matrix.get("include")
    if isinstance(include, list):
        for entry in include:
            entry = _mapping(entry)
            if isinstance(entry.get(key), (str, int, float)):
                values.append(str(entry[key]))
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
    written = uses.strip()  # as it appears in the workflow, for the message
    if written.startswith("./") or written.startswith("../"):
        return
    host, ref = _normalise_action(written)
    action = ref.split("@", 1)[0]
    on_github = host == GITHUB_HOST

    # A rule only counts as covering the action when it fired: a rule that does
    # not apply to this target leaves the action unchecked, so it has to fall
    # through to unknown-action rather than silently disappear.
    covered = False
    # The v4 artifact rule is github.com-only on purpose: the same path on
    # another forge is the patched fork its own fix hint recommends.
    if on_github and ARTIFACT_V4_RE.match(ref):
        covered = emitter.emit("artifact-actions-v4", file, job=job, step=step, uses=written)
    for pattern, rule_id in GITHUB_ONLY_ACTIONS:
        # these talk to a GitHub service, so a mirror on another host is no better
        if _matches_action(action, pattern):
            covered = emitter.emit(rule_id, file, job=job, step=step, uses=written) or covered
            break

    if in_container and action.startswith(JS_ACTION_PREFIX):
        emitter.emit("container-js-action-node", file, job=job, step=step, uses=written)

    key = action if on_github else f"{host}/{action}"
    if not covered and key not in seen_unknown:
        seen_unknown.add(key)
        emitter.emit("unknown-action", file, job=job, step=step, action=key)


def _matches_action(action: str, pattern: str) -> bool:
    """Match an ``owner/repo[/path]`` action against a GITHUB_ONLY_ACTIONS pattern."""
    if pattern.endswith("*"):
        return action.startswith(pattern[:-1])
    return action == pattern or action.startswith(pattern + "/")


def _normalise_action(uses: str) -> tuple[str, str]:
    """Split a ``uses:`` into its host and its ``owner/repo[/path][@ref]`` part.

    ``https://github.com/actions/checkout@v4``, ``github.com/actions/checkout@v4``
    and the bare ``actions/checkout@v4`` all give ``("github.com", "actions/checkout@v4")``;
    ``https://code.forgejo.org/actions/checkout@v4`` gives that host with the same
    path, so a rule can match on the action itself and still tell the forges apart.
    """
    ref = uses
    scheme = USES_SCHEME_RE.match(ref)
    if scheme:
        ref = ref[scheme.end() :]
    head, sep, rest = ref.partition("/")
    if sep and (scheme or "." in head) and HOSTNAME_RE.match(head):
        host = head.lower().removeprefix("www.")
        return host, rest
    return GITHUB_HOST, ref


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
