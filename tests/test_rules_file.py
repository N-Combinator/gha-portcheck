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

# Hosts that belong to Forgejo or Gitea themselves; a source on one of these
# describes the behaviour on the target rather than on GitHub.
FORGE_HOSTS = {"forgejo.org", "codeberg.org", "docs.gitea.com", "gitea.com", "forum.gitea.com"}

# github.com paths that are still an upstream Forgejo/Gitea source (issue, PR,
# release notes or the code itself), not GitHub's own documentation.
UPSTREAM_GITHUB_PREFIXES = ("/go-gitea/", "/forgejo/")

# What a rule has to say in its message when no Forgejo/Gitea page documents the
# gap at all, so a reader is not left with a github.com link and no explanation.
GITHUB_ONLY_DISCLOSURE = "GitHub-only service, no Forgejo/Gitea equivalent documented"

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


@pytest.mark.parametrize("entry", ENTRIES, ids=[e["id"] for e in ENTRIES])
def test_primary_source_covers_forgejo_or_gitea(entry):
    """The source_url has to state the behaviour on the target, not on GitHub."""
    url = urlparse(entry["source_url"])
    if url.hostname in FORGE_HOSTS:
        return
    assert url.hostname == "github.com", entry["id"]
    if url.path.startswith(UPSTREAM_GITHUB_PREFIXES):
        return
    assert GITHUB_ONLY_DISCLOSURE in entry["message"], entry["id"]


def test_attestations_rule_is_sourced_and_disclosed():
    """Neither forge documents an attestation store, so the rule says so itself."""
    rule = rules_mod.get("github-only-attestations")
    assert urlparse(rule.source_url).hostname in FORGE_HOSTS
    assert GITHUB_ONLY_DISCLOSURE in rule.message


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
