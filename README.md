# gha-portcheck

Check which parts of GitHub Actions workflows will not work on Forgejo or Gitea Actions.

`gha-portcheck` reads the workflow files in a repository and prints the things that a
maintainer has to deal with **before** migrating to [Forgejo Actions](https://forgejo.org/docs/latest/user/actions/)
or [Gitea Actions](https://docs.gitea.com/usage/actions/overview): runner labels that
only exist on GitHub, actions backed by GitHub-only services, events that are named
differently, and so on. It is static: it never runs a workflow, never fetches an action
and makes no network calls at all.

## Install

From a checkout:

```console
$ pip install .
```

From a [GitHub Release](https://github.com/N-Combinator/gha-portcheck/releases) wheel
(each `v*` tag attaches an sdist and a wheel):

```console
$ pip install https://github.com/N-Combinator/gha-portcheck/releases/download/v0.1.0/gha_portcheck-0.1.0-py3-none-any.whl
```

Python ≥ 3.10; the only runtime dependency is PyYAML.

## Usage

```console
$ gha-portcheck scan . --target forgejo
$ gha-portcheck scan /path/to/repo --target gitea --format markdown
$ gha-portcheck scan . --target forgejo --fail-on error   # exit 1 if an error was found
$ gha-portcheck rules
$ gha-portcheck rules --explain artifact-actions-v4
```

`scan` reads every `*.yml`/`*.yaml` in `.github/workflows/`, and also in
`.forgejo/workflows/` and `.gitea/workflows/` when those directories exist. YAML is
parsed with PyYAML's safe loader, so anchors and aliases are resolved.

Findings are printed as a JSON list (`--format json`, the default) or as a table
(`--format markdown`), sorted by file, job, step and rule:

```json
[
  {
    "file": ".github/workflows/release.yml",
    "job": "build",
    "step": 3,
    "rule": "artifact-actions-v4",
    "severity": "error",
    "message": "`actions/upload-artifact@v4` uses the v4 artifact API; the Forgejo documentation requires v3 ...",
    "fix_hint": "Pin `actions/upload-artifact@v3` / `actions/download-artifact@v3`, ...",
    "source_url": "https://forgejo.org/docs/latest/user/actions/advanced-features/#artifacts"
  }
]
```

Exit codes:

| code | meaning |
|---|---|
| 0 | scan completed (default), or `--fail-on` threshold not reached |
| 1 | `--fail-on error` and an error was found, or `--fail-on warning` and a warning or error was found |
| 2 | a workflow file is not valid YAML (reported as `path:line` on stderr) or not valid UTF-8 (reported as `path: not valid UTF-8`), the path is not a directory, or an unknown rule id was passed to `rules --explain` |

A repository without workflow files exits 0 with an empty finding list and a warning on
stderr.

## Rules

Rules live in a packaged [`rules.json`](src/gha_portcheck/rules.json); `gha-portcheck rules`
lists them and `--explain <id>` prints one in full. Each rule carries one `source_url`
that states the behaviour, plus `see_also` links covering the other target where a single
page does not cover both.

| rule | targets | severity | what it catches | source |
|---|---|---|---|---|
| `runs-on-github-hosted-label` | forgejo, gitea | warning | `runs-on:` values such as `ubuntu-latest`, `macos-14`, `windows-2022`, `*-arm`, including values reachable through `strategy.matrix` lists and `include` | [Forgejo runs-on reference](https://forgejo.org/docs/latest/user/actions/reference/#jobsjob_idruns-on), [Gitea runner labels](https://docs.gitea.com/runner/labels) |
| `artifact-actions-v4` | forgejo | error | `actions/upload-artifact@v4`, `actions/download-artifact@v4` | [Forgejo artifacts docs](https://forgejo.org/docs/latest/user/actions/advanced-features/#artifacts), [Gitea 1.22 release notes](https://github.com/go-gitea/gitea/releases/tag/v1.22.0) |
| `github-only-codeql` | forgejo, gitea | error | `github/codeql-action/*` (GitHub code scanning) | [Forgejo issue #12667](https://codeberg.org/forgejo/forgejo/issues/12667), [Gitea token permissions](https://docs.gitea.com/usage/actions/token-permissions#compatibility-notes) |
| `github-only-attestations` | forgejo, gitea | error | `actions/attest-build-provenance`, other `actions/attest*` | [attest-build-provenance](https://github.com/actions/attest-build-provenance), [Gitea token permissions](https://docs.gitea.com/usage/actions/token-permissions#compatibility-notes) |
| `github-only-pages` | forgejo, gitea | error | `actions/deploy-pages`, `actions/upload-pages-artifact`, `actions/configure-pages` | [Forgejo issue #2708](https://codeberg.org/forgejo/forgejo/issues/2708), [Gitea token permissions](https://docs.gitea.com/usage/actions/token-permissions#compatibility-notes) |
| `oidc-id-token` | forgejo, gitea | warning | `permissions:` with `id-token: write` | [Forgejo differences](https://forgejo.org/docs/latest/user/actions/github-actions/#known-list-of-differences), [Gitea token permissions](https://docs.gitea.com/usage/actions/token-permissions#compatibility-notes) |
| `job-environment` | gitea | warning | job-level `environment:` | [Gitea comparison](https://docs.gitea.com/usage/actions/comparison#jobsjob_idenvironment) |
| `pull-request-labeled-types` | forgejo, gitea | info | `on.pull_request.types` containing `labeled`/`unlabeled` | [Gitea workflows.go](https://github.com/go-gitea/gitea/blob/4892a55e2915be979b892491352ecb610458dd1b/modules/actions/workflows.go#L552-L570), [Forgejo workflows.go](https://codeberg.org/forgejo/forgejo/src/commit/df600c18162beb2156c4977e84e0b7131c2938f8/modules/actions/workflows.go#L456-L474) |
| `container-js-action-node` | forgejo, gitea | warning | a job with `container:` that uses an `actions/*` JavaScript action | [Forgejo container.image reference](https://forgejo.org/docs/latest/user/actions/reference/#jobsjob_idcontainerimage), [Gitea forum](https://forum.gitea.com/t/use-actions-checkout-v3-in-a-container-without-node-installed/8406) |
| `github-api-in-run` | forgejo, gitea | warning | a `run:` step containing `api.github.com` or invoking `gh` | [Gitea actions variables](https://docs.gitea.com/usage/actions/actions-variables#environment-variables), [Forgejo github context](https://forgejo.org/docs/latest/user/actions/reference/#github) |
| `unknown-action` | forgejo, gitea | info | every other `uses:` (local `./` actions excluded), once per action | [Gitea: downloading actions](https://docs.gitea.com/usage/actions/comparison#downloading-actions), [Forgejo differences](https://forgejo.org/docs/latest/user/actions/github-actions/#known-list-of-differences) |

Two notes on rules that are deliberately target-specific or surprising:

- `artifact-actions-v4` is a Forgejo-only error because Gitea implements the v4 artifact
  backend since [1.22](https://github.com/go-gitea/gitea/releases/tag/v1.22.0).
- `pull-request-labeled-types` exists because both forges derive the GitHub type names
  from their own `label_updated`/`label_cleared` events: on a pull request, `labeled`
  fires for label removals too and `unlabeled` only arrives when the labels are cleared.
  Neither project documents this in prose, so the source links point at the mapping in
  their code.

### Target versions

The rules were written against **Forgejo v16.0 documentation (forgejo.org/docs/latest)** and **Gitea 1.27 documentation (docs.gitea.com)**. Both projects
move fast: a rule may describe a gap that your version has already closed, so check the
linked source against the version you are migrating to.

### These findings are a checklist, not a guarantee

`gha-portcheck` only looks at workflow YAML. An empty report does not mean your
workflows will run on Forgejo or Gitea — it means none of the rules above matched. What
an action does at runtime (GitHub API calls, GitHub-only tooling, the software installed
on the runner image) is out of reach of a static check, which is why every `uses:` that
has no rule is reported as `unknown-action` rather than silently accepted. Nothing is
ever reported as verified-OK.

## Similar tools

- [`act`](https://github.com/nektos/act) — runs GitHub Actions workflows locally; useful
  to find out what actually breaks, but it executes the workflow rather than reviewing it.
- [`actionlint`](https://github.com/rhysd/actionlint) — static checker for GitHub Actions
  workflows (syntax, expressions, shell). It checks validity on GitHub, not portability
  away from it, and the two are complementary.
- [`forgejo-runner`](https://forgejo.org/docs/latest/admin/actions/) /
  [`act_runner`](https://docs.gitea.com/usage/actions/act-runner) — the runners
  themselves; running a workflow on one is the ground truth this tool approximates.

## Development

```console
$ python -m venv .venv && . .venv/bin/activate
$ pip install -e ".[dev]"
$ pytest -q
```

## License

MIT, see [LICENSE](LICENSE).
