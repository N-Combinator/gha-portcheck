"""Integrity of the packaged rules.json (no network access, structure only)."""

from __future__ import annotations

import json
from urllib.parse import urlparse

import pytest

from gha_portcheck import rules as rules_mod

REQUIRED_FIELDS = {"id", "targets", "severity", "message", "fix_hint", "source_url"}

# Hosts we accept as a source. code.forgejo.org is deliberately excluded: it sits
# behind an anti-bot wall, so a reader cannot check the claim.
ALLOWED_HOSTS = {
    "forgejo.org",
    "codeberg.org",
    "docs.gitea.com",
    "gitea.com",
    "github.com",
    "forum.gitea.com",
}

RAW = json.loads(rules_mod.rules_json_text())
ENTRIES = RAW["rules"]


def test_rules_json_is_a_list_of_rules():
    assert isinstance(ENTRIES, list) and len(ENTRIES) >= 9
    ids = [entry["id"] for entry in ENTRIES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("entry", ENTRIES, ids=[e["id"] for e in ENTRIES])
def test_rule_has_all_fields(entry):
    assert REQUIRED_FIELDS <= set(entry) <= REQUIRED_FIELDS | {"see_also"}
    assert entry["id"] and isinstance(entry["id"], str)
    assert entry["targets"] and set(entry["targets"]) <= set(rules_mod.TARGETS)
    assert entry["severity"] in rules_mod.SEVERITIES
    assert entry["message"].strip()
    assert entry["fix_hint"].strip()


@pytest.mark.parametrize("entry", ENTRIES, ids=[e["id"] for e in ENTRIES])
def test_rule_source_url(entry):
    for candidate in [entry["source_url"], *entry.get("see_also", [])]:
        url = urlparse(candidate)
        assert url.scheme == "https", candidate
        assert url.hostname in ALLOWED_HOSTS, candidate


def test_required_v0_1_rules_are_present():
    expected = {
        "runs-on-github-hosted-label": ["forgejo", "gitea"],
        "artifact-actions-v4": ["forgejo"],
        "github-only-codeql": ["forgejo", "gitea"],
        "github-only-attestations": ["forgejo", "gitea"],
        "github-only-pages": ["forgejo", "gitea"],
        "oidc-id-token": ["forgejo", "gitea"],
        "job-environment": ["gitea"],
        "pull-request-labeled-types": ["forgejo", "gitea"],
        "container-js-action-node": ["forgejo", "gitea"],
        "unknown-action": ["forgejo", "gitea"],
        "github-api-in-run": ["forgejo", "gitea"],
    }
    catalogue = rules_mod.load_rules()
    for rule_id, targets in expected.items():
        assert rule_id in catalogue, rule_id
        assert list(catalogue[rule_id].targets) == targets, rule_id


def test_rule_messages_only_use_known_placeholders():
    import string

    allowed = {"label", "uses", "action", "types", "what"}
    for entry in ENTRIES:
        fields = {
            name
            for _, name, _, _ in string.Formatter().parse(entry["message"])
            if name is not None
        }
        assert fields <= allowed, (entry["id"], fields)


def test_readme_documents_every_rule():
    from pathlib import Path

    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
    for entry in ENTRIES:
        assert f"`{entry['id']}`" in readme, entry["id"]
        assert entry["source_url"] in readme, entry["id"]
