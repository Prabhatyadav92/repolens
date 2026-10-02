from __future__ import annotations

from collections import Counter
from datetime import datetime

from .models import RULES, SEVERITY_ORDER


def sort_findings(findings):
    return sorted(findings, key=lambda x: (-SEVERITY_ORDER[x.severity], x.path, x.line))


def render(result, quality, leaks) -> str:
    langs = sorted(result.languages().items(), key=lambda kv: -kv[1][1])
    total_files = sum(v[0] for v in result.languages().values())
    total_lines = sum(v[1] for v in result.languages().values())

    out = [
        f"# {result.root.name}",
        "",
        f"RepoLens report, {datetime.now():%Y-%m-%d %H:%M}. Scanned `{result.root}`.",
        "",
        "## Size",
        "",
        f"{total_files:,} files, {total_lines:,} non-blank lines.",
        "",
        "| Language | Files | Lines |",
        "| --- | ---: | ---: |",
    ]
    out += [f"| {name} | {n:,} | {lines:,} |" for name, (n, lines) in langs]

    notes = _project_notes(result)
    out += ["", "## Project", ""] + [f"- {n}" for n in notes]

    out += ["", f"## Secrets ({len(leaks)})", ""]
    out += _table(sort_findings(leaks)) if leaks else ["Nothing that looks like a secret was found."]

    out += ["", f"## Code findings ({len(quality)})", ""]
    out += _table(sort_findings(quality)) if quality else ["No findings."]

    used = Counter(x.rule for x in quality + leaks)
    if used:
        out += ["", "## Rules that fired", ""]
        out += [f"- `{rule}` ({count}): {RULES.get(rule, '')}" for rule, count in used.most_common()]

    out += ["", "Secret values are masked in this report.", ""]
    return "\n".join(out)


def _table(findings):
    rows = ["| Where | Rule | Severity | Detail |", "| --- | --- | --- | --- |"]
    for x in findings:
        detail = x.message.replace("|", "\\|")
        rows.append(f"| `{x.location}` | {x.rule} | {x.severity} | {detail} |")
    return rows


def _project_notes(result):
    notes = []
    if result.manifests():
        notes.append("Dependency files: " + ", ".join(f"`{m}`" for m in result.manifests()))
    if result.missing():
        notes.append("Not found: " + ", ".join(result.missing()))
    ignored = len(result.files) - len(result.counted)
    if ignored:
        notes.append(f"{ignored} generated or minified files were left out of the counts.")
    if result.skipped:
        notes.append(f"{result.skipped} files were skipped (too large or unreadable).")
    return notes
