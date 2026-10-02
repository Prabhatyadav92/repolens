from __future__ import annotations

from dataclasses import dataclass

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    message: str
    severity: str = "low"
    kind: str = "quality"  # "quality" or "secret"

    @property
    def location(self) -> str:
        return f"{self.path}:{self.line}"


@dataclass(frozen=True)
class Limits:
    max_function_lines: int = 60
    max_complexity: int = 15
    max_args: int = 7


# One line per rule, used by `repolens rules` and the report.
RULES = {
    "long-function": "Function is longer than the limit. Long functions are hard to read and test.",
    "complexity": "Too many branches in one function. Early returns or helpers usually help.",
    "many-args": "Function takes many parameters. Group related ones or use keyword arguments.",
    "unused-import": "Imported name is never used in the file.",
    "bare-except": "A bare 'except:' also swallows KeyboardInterrupt and SystemExit.",
    "mutable-default": "A mutable default argument is shared between calls.",
    "eval-call": "eval/exec runs arbitrary code. Avoid it for anything not fully trusted.",
    "empty-catch": "An empty catch block hides errors.",
    "use-var": "'var' is function scoped; let or const are safer.",
    "loose-equality": "'==' and '!=' coerce types; '===' and '!==' do not.",
    "console-log": "Many console.log calls, probably leftover debugging.",
    "todo": "A TODO/FIXME/HACK/XXX marker in a comment.",
    "syntax-error": "The file could not be parsed.",
    "env-file": "A .env file that .gitignore does not cover.",
    "private-key": "A PEM private key block.",
    "aws-access-key": "An AWS access key ID.",
    "github-token": "A GitHub personal access or app token.",
    "slack-token": "A Slack API token.",
    "google-api-key": "A Google API key.",
    "stripe-key": "A live Stripe key.",
    "api-key": "A long 'sk-' style secret key.",
    "jwt": "A JSON web token.",
    "db-url-credentials": "A database URL with a password in it.",
    "hardcoded-secret": "A password, token or key assigned a literal value.",
}
