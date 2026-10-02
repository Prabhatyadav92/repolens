from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, analyze, report, secrets
from .models import RULES, SEVERITY_ORDER, Limits
from .scanner import scan

COMMANDS = {"scan", "secrets", "report", "rules"}
SHOW_LIMIT = 20


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("path", nargs="?", default=".", help="directory to look at (default: .)")
    common.add_argument("-x", "--exclude", action="append", default=[], metavar="GLOB",
                        help="skip files or directories matching GLOB; may be given more than once")
    common.add_argument("--max-function-lines", type=int, default=60, metavar="N")
    common.add_argument("--max-complexity", type=int, default=15, metavar="N")
    common.add_argument("--max-args", type=int, default=7, metavar="N")

    parser = argparse.ArgumentParser(
        prog="repolens",
        description="Summarize a source tree: size, code problems and leaked secrets.",
    )
    parser.add_argument("--version", action="version", version=f"repolens {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="command")

    p = sub.add_parser("scan", parents=[common], help="print a summary and the findings (default)")
    p.add_argument("--all", action="store_true", help=f"show every finding, not just the first {SHOW_LIMIT}")
    p.add_argument("--fail-on", choices=list(SEVERITY_ORDER), metavar="LEVEL",
                   help="exit 1 if there is a finding at LEVEL (low, medium, high) or above")

    sub.add_parser("secrets", parents=[common], help="only look for secrets; exit 1 if any are found")

    p = sub.add_parser("report", parents=[common], help="write a Markdown report")
    p.add_argument("-o", "--output", default="repolens-report.md", metavar="FILE")

    sub.add_parser("rules", help="list what is checked")
    return parser


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0] not in COMMANDS and argv[0] not in ("-h", "--help", "--version")):
        argv.insert(0, "scan")
    args = build_parser().parse_args(argv)

    if args.command == "rules":
        return _print_rules()

    root = Path(args.path)
    if not root.is_dir():
        print(f"repolens: {args.path}: not a directory", file=sys.stderr)
        return 2

    limits = Limits(args.max_function_lines, args.max_complexity, args.max_args)
    result = scan(root, args.exclude)
    leaks = secrets.scan(result)

    if args.command == "secrets":
        _print_findings("Secrets", leaks, show_all=True)
        if not leaks:
            print("No secrets found.")
        return 1 if leaks else 0

    quality = analyze.run(result.files, limits)

    if args.command == "report":
        Path(args.output).write_text(report.render(result, quality, leaks), encoding="utf-8")
        print(f"Wrote {args.output} ({len(quality)} findings, {len(leaks)} possible secrets)")
        return 0

    _print_scan(result, quality, leaks, show_all=args.all)
    if args.fail_on:
        bar = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[x.severity] >= bar for x in quality + leaks):
            return 1
    return 0


def _print_scan(result, quality, leaks, show_all):
    print(f"Scanning {result.root}\n")
    _print_languages(result)
    _print_project(result)
    _print_findings("Secrets", leaks, show_all=True)
    _print_findings("Findings", quality, show_all=show_all)
    print(f"{len(quality)} findings, {len(leaks)} possible secrets. Run `repolens report` for a file.")


def _print_languages(result):
    rows = sorted(result.languages().items(), key=lambda kv: -kv[1][1])
    if not rows:
        print("No source files found.\n")
        return
    rows.append(("Total", (sum(v[0] for _, v in rows), sum(v[1] for _, v in rows))))
    files = [f"{n} file" + ("" if n == 1 else "s") for _, (n, _) in rows]
    lines = [f"{n:,} line" + ("" if n == 1 else "s") for _, (_, n) in rows]
    width = max(len(name) for name, _ in rows)
    fw, lw = max(map(len, files)), max(map(len, lines))
    print("Languages")
    for (name, _), fcol, lcol in zip(rows, files, lines):
        if name == "Total":
            print()
        print(f"  {name:<{width}}  {fcol:>{fw}}  {lcol:>{lw}}")
    print()


def _print_project(result):
    lines = []
    if result.manifests():
        lines.append("dependency files: " + ", ".join(result.manifests()[:6]))
    if result.missing():
        lines.append("not found: " + ", ".join(result.missing()))
    hidden = len(result.files) - len(result.counted)
    if hidden:
        lines.append(f"{hidden} generated/minified files not counted")
    if lines:
        print("Project")
        for line in lines:
            print("  " + line)
        print()


def _print_findings(title, findings, show_all):
    if not findings:
        return
    ordered = report.sort_findings(findings)
    shown = ordered if show_all else ordered[:SHOW_LIMIT]
    print(f"{title} ({len(findings)})")
    loc_w = min(max(len(x.location) for x in shown), 44)
    rule_w = max(len(x.rule) for x in shown)
    for x in shown:
        loc = x.location if len(x.location) <= loc_w else "..." + x.location[-(loc_w - 3):]
        print(f"  {loc:<{loc_w}}  {x.rule:<{rule_w}}  {x.message}")
    if len(shown) < len(ordered):
        print(f"  ... {len(ordered) - len(shown)} more (use --all)")
    print()


def _print_rules() -> int:
    width = max(map(len, RULES))
    for name, text in RULES.items():
        print(f"{name:<{width}}  {text}")
    return 0
