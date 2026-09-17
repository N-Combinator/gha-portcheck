"""Command line interface for gha-portcheck."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from . import rules as rules_mod
from .loader import WorkflowParseError
from .scanner import Finding, scan_repo

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gha-portcheck",
        description=(
            "Report which parts of a repository's GitHub Actions workflows will not "
            "work on Forgejo Actions or Gitea Actions."
        ),
    )
    parser.add_argument("--version", action="version", version=f"gha-portcheck {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a repository's workflow files")
    scan.add_argument("repo", type=Path, help="path to the repository to scan")
    scan.add_argument(
        "--target",
        required=True,
        choices=list(rules_mod.TARGETS),
        help="the forge the workflows are being migrated to",
    )
    scan.add_argument("--format", default="json", choices=("json", "markdown"))
    scan.add_argument(
        "--fail-on",
        choices=("error", "warning"),
        help="exit 1 when a finding of this severity or higher exists",
    )

    rules = sub.add_parser("rules", help="list the rule catalogue")
    rules.add_argument("--explain", metavar="ID", help="print a single rule")
    rules.add_argument("--format", default="text", choices=("text", "json"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    return _cmd_rules(args)


def _cmd_scan(args: argparse.Namespace) -> int:
    repo: Path = args.repo
    if not repo.is_dir():
        print(f"gha-portcheck: {repo}: not a directory", file=sys.stderr)
        return EXIT_ERROR
    try:
        findings, scanned = scan_repo(repo, args.target)
    except WorkflowParseError as exc:
        print(f"gha-portcheck: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not scanned:
        print(
            f"gha-portcheck: no workflow files found under {repo}",
            file=sys.stderr,
        )

    if args.format == "json":
        print(json.dumps([f.as_dict() for f in findings], indent=2))
    else:
        print(render_markdown(findings, args.target))

    if args.fail_on:
        threshold = rules_mod.severity_rank(args.fail_on)
        if any(rules_mod.severity_rank(f.severity) >= threshold for f in findings):
            return EXIT_FINDINGS
    return EXIT_OK


def render_markdown(findings: list[Finding], target: str) -> str:
    lines = [f"# gha-portcheck: {target}", ""]
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines)
    counts = {severity: 0 for severity in rules_mod.SEVERITIES}
    for finding in findings:
        counts[finding.severity] += 1
    lines.append(
        ", ".join(
            f"{counts[s]} {s}" for s in reversed(rules_mod.SEVERITIES) if counts[s]
        )
    )
    lines += ["", "| file | job | step | rule | severity | message | fix hint | source |", "|---|---|---|---|---|---|---|---|"]
    for f in findings:
        lines.append(
            "| {file} | {job} | {step} | {rule} | {severity} | {message} | {fix} | [source]({url}) |".format(
                file=f.file,
                job=f.job or "-",
                step="-" if f.step is None else f.step,
                rule=f.rule,
                severity=f.severity,
                message=_md_cell(f.message),
                fix=_md_cell(f.fix_hint),
                url=f.source_url,
            )
        )
    return "\n".join(lines)


def _md_cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _cmd_rules(args: argparse.Namespace) -> int:
    catalogue = rules_mod.load_rules()
    if args.explain:
        rule = catalogue.get(args.explain)
        if rule is None:
            print(f"gha-portcheck: unknown rule: {args.explain}", file=sys.stderr)
            return EXIT_ERROR
        if args.format == "json":
            print(json.dumps(rule.as_dict(), indent=2))
        else:
            print(_explain(rule))
        return EXIT_OK

    if args.format == "json":
        print(json.dumps([r.as_dict() for r in catalogue.values()], indent=2))
        return EXIT_OK
    for rule in catalogue.values():
        print(f"{rule.id:34} {rule.severity:8} {','.join(rule.targets)}")
    return EXIT_OK


def _explain(rule: rules_mod.Rule) -> str:
    return "\n".join(
        [
            f"id:        {rule.id}",
            f"targets:   {', '.join(rule.targets)}",
            f"severity:  {rule.severity}",
            f"message:   {rule.message}",
            f"fix_hint:  {rule.fix_hint}",
            f"source:    {rule.source_url}",
        ]
        + [f"see also:  {url}" for url in rule.see_also]
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
