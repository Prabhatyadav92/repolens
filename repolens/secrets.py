from __future__ import annotations

import re

from .models import Finding

# (rule, pattern, severity, label)
SPECIFIC = [
    ("private-key", re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----"), "high", "private key block"),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "high", "AWS access key"),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"), "high", "GitHub token"),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "high", "Slack token"),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high", "Google API key"),
    ("stripe-key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b"), "high", "Stripe live key"),
    ("api-key", re.compile(r"\bsk-[A-Za-z0-9_\-]{32,}"), "high", "secret key"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "medium", "JSON web token"),
    ("db-url-credentials",
     re.compile(r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s:/@'\"]+:([^\s@'\"]{3,})@"),
     "high", "database URL with password"),
]

NAME = r"[\w.-]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|token|private[_-]?key)[\w.-]*"
ASSIGNMENT = re.compile(r"(?<![\w\\.-])(" + NAME + r")[\"']?\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']", re.I)
ENV_LINE = re.compile(r"^\s*(?:export\s+)?(" + NAME.replace("[\\w.-]*", "[A-Z0-9_]*") + r")\s*=\s*(\S{8,})\s*$", re.I)

FAKE_WORDS = (
    "example", "changeme", "change_me", "change-me", "your", "xxxx", "placeholder",
    "dummy", "sample", "fake", "redacted", "<", "{{", "${", "process.env", "os.environ", "getenv",
)
FAKE_EXACT = {"password", "pass", "secret", "root", "admin", "postgres", "user"}
PLAIN_WORD = re.compile(r"[A-Za-z]+(?:[_.\-][A-Za-z]+)*")
ENV_FILE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults")


def is_env_file(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return (name == ".env" or name.startswith(".env.")) and not name.endswith(ENV_FILE_SUFFIXES)


def _fake(value: str) -> bool:
    v = value.lower()
    return v in FAKE_EXACT or any(w in v for w in FAKE_WORDS) or len(set(v)) <= 2


def _mask(value: str) -> str:
    return value[:4] + "*" * 8


def scan(result) -> list[Finding]:
    findings = []
    for f in result.counted:
        env = is_env_file(f.path)
        if env:
            findings.append(Finding(f.path, 1, "env-file",
                                    "environment file is not covered by .gitignore", "medium", "secret"))
        for number, line in enumerate(f.text.splitlines(), 1):
            if len(line) > 2000 or "repolens: ignore" in line:
                continue
            findings.extend(_scan_line(f.path, number, line, env))
    return _collapse(findings)


def _collapse(findings, keep=3):
    """A seed file with eleven identical demo passwords should read as one problem."""
    groups = {}
    for x in findings:
        groups.setdefault((x.path, x.rule), []).append(x)
    out = []
    for items in groups.values():
        if items[0].rule != "hardcoded-secret" or len(items) <= keep:
            out.extend(items)
            continue
        first = items[0]
        extra = len(items) - 1
        out.append(Finding(first.path, first.line, first.rule,
                           f"{first.message} (and {extra} more in this file)", first.severity, first.kind))
    return out


def _scan_line(path, number, line, env):
    hits = _scan_known(path, number, line)
    if hits:
        return hits
    if env:
        return _scan_env_line(path, number, line)
    return _scan_assignments(path, number, line)


def _scan_known(path, number, line):
    hits = []
    for rule, rx, severity, label in SPECIFIC:
        for m in rx.finditer(line):
            secret = m.group(1) if rx.groups else m.group(0)
            if rule != "private-key" and _fake(secret):
                continue
            text = label if rule == "private-key" else f"{label}: {_mask(m.group(0))}"
            hits.append(Finding(path, number, rule, text, severity, "secret"))
    return hits


def _scan_env_line(path, number, line):
    m = ENV_LINE.match(line)
    if not m:
        return []
    value = m.group(2).strip("'\"")
    if not value or value.startswith("$") or _fake(value):
        return []
    return [Finding(path, number, "hardcoded-secret", f"value for {m.group(1)}: {_mask(value)}", "medium", "secret")]


def _scan_assignments(path, number, line):
    hits = []
    for m in ASSIGNMENT.finditer(line):
        name, value = m.group(1), m.group(2)
        if _fake(value) or PLAIN_WORD.fullmatch(value):
            continue
        hits.append(Finding(path, number, "hardcoded-secret", f"value for {name}: {_mask(value)}", "medium", "secret"))
    return hits