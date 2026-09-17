"""Access to the packaged rule catalogue (``rules.json``)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

TARGETS = ("forgejo", "gitea")
SEVERITIES = ("info", "warning", "error")


@dataclass(frozen=True)
class Rule:
    id: str
    targets: tuple[str, ...]
    severity: str
    message: str
    fix_hint: str
    source_url: str
    see_also: tuple[str, ...] = ()

    def applies_to(self, target: str) -> bool:
        return target in self.targets

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "targets": list(self.targets),
            "severity": self.severity,
            "message": self.message,
            "fix_hint": self.fix_hint,
            "source_url": self.source_url,
            "see_also": list(self.see_also),
        }


def rules_json_text() -> str:
    return resources.files(__package__).joinpath("rules.json").read_text(encoding="utf-8")


@lru_cache(maxsize=1)
def load_rules() -> dict[str, Rule]:
    """Return the packaged rules keyed by id, in file order."""
    raw = json.loads(rules_json_text())
    rules: dict[str, Rule] = {}
    for entry in raw["rules"]:
        rule = Rule(
            id=entry["id"],
            targets=tuple(entry["targets"]),
            severity=entry["severity"],
            message=entry["message"],
            fix_hint=entry["fix_hint"],
            source_url=entry["source_url"],
            see_also=tuple(entry.get("see_also", ())),
        )
        rules[rule.id] = rule
    return rules


def get(rule_id: str) -> Rule:
    return load_rules()[rule_id]


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)
