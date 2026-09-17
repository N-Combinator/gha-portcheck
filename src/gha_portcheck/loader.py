"""Discovery and safe loading of workflow files."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml

WORKFLOW_DIRS = (
    ".github/workflows",
    ".forgejo/workflows",
    ".gitea/workflows",
)

WORKFLOW_SUFFIXES = (".yml", ".yaml")


class WorkflowParseError(Exception):
    """Raised when a workflow file cannot be read or is not valid YAML.

    ``line`` is ``None`` when the problem has no position, such as a file that
    is not UTF-8 at all.
    """

    def __init__(self, path: str, line: int | None, detail: str) -> None:
        self.path = path
        self.line = line
        self.detail = detail
        location = path if line is None else f"{path}:{line}"
        super().__init__(f"{location}: {detail}")


@dataclass(frozen=True)
class Workflow:
    """One parsed workflow file."""

    path: str  # repo-relative, POSIX separators
    data: dict


def discover(repo: Path) -> list[Path]:
    """Return the workflow files of ``repo``, sorted by repo-relative path."""
    found: list[Path] = []
    for rel_dir in WORKFLOW_DIRS:
        directory = repo / rel_dir
        if not directory.is_dir():
            continue
        for entry in directory.iterdir():
            if entry.is_file() and entry.suffix in WORKFLOW_SUFFIXES:
                found.append(entry)
    return sorted(found, key=lambda p: relpath(p, repo))


def relpath(path: Path, repo: Path) -> str:
    return os.path.relpath(path, repo).replace(os.sep, "/")


def load(path: Path, display_path: str | None = None) -> Workflow:
    """Parse one workflow file with PyYAML's safe loader.

    Anchors and aliases are resolved by the loader itself; only merge-free,
    tag-free YAML is accepted (``SafeLoader`` refuses arbitrary Python tags).
    """
    shown = display_path or str(path)
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise WorkflowParseError(shown, None, "not valid UTF-8") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None) or getattr(exc, "context_mark", None)
        line = (mark.line + 1) if mark is not None else 1
        detail = getattr(exc, "problem", None) or str(exc).splitlines()[0]
        raise WorkflowParseError(shown, line, detail) from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise WorkflowParseError(shown, 1, "workflow is not a mapping")
    return Workflow(path=shown, data=data)
