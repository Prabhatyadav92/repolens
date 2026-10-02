from __future__ import annotations

import re

from . import jsanalyzer, pyanalyzer
from .models import Finding, Limits

COMMENTED_LANGS = {
    "Python", "JavaScript", "TypeScript", "Java", "Go", "Rust", "Ruby", "PHP", "C", "C++",
    "C#", "Shell", "SQL", "HTML", "CSS", "SCSS", "YAML", "TOML",
}
MARKER = re.compile(r"(?:#|//|/\*|<!--|^\s*\*)[^\n]*?\b(TODO|FIXME|HACK|XXX)\b[:\s(-]*(.*)")  # repolens: ignore


def run(files, limits: Limits) -> list[Finding]:
    findings = []
    for f in files:
        if f.generated:
            continue
        if f.language == "Python":
            findings.extend(pyanalyzer.check(f, limits))
        elif f.language == "JavaScript":
            findings.extend(jsanalyzer.check(f, limits))
        if f.language in COMMENTED_LANGS:
            findings.extend(_markers(f))
    return findings


def _markers(f):
    out = []
    for number, line in enumerate(f.text.splitlines(), 1):
        if "repolens: ignore" in line:
            continue
        m = MARKER.search(line)
        if m:
            note = m.group(2).strip().rstrip("*/-> ").strip()[:60]
            out.append(Finding(f.path, number, "todo", f"{m.group(1)} {note}".strip()))
    return out
