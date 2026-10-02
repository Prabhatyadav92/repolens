"""Regex based checks for JavaScript.

There is no real parser here. Comments and strings are blanked out first so
braces inside them don't throw off the function-length counting, but regex
literals can still fool it. When braces don't balance, a function is skipped
rather than guessed at.
"""
from __future__ import annotations

import bisect
import re

from .models import Finding, Limits

_NON_NEWLINE = re.compile(r"[^\n]")
_SPECIAL = re.compile(r"[/'\"`]")
_KEYWORDS = {"if", "for", "while", "switch", "catch", "function", "return", "with"}

_PATTERNS = [
    (re.compile(r"\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*(?=\()"), "fn"),
    (re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?function\b"), "fn"),
    (re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?"
                r"(?:\([^()]*\)|[A-Za-z_$][\w$]*)\s*=>"), "arrow"),
    (re.compile(r"\bfunction\s*\*?\s*(?=\()"), "fn"),
    (re.compile(r"(?:\([^()]*\)|\b[A-Za-z_$][\w$]*)\s*=>"), "arrow"),
    (re.compile(r"^[ \t]*(?:(?:static|async|get|set)\s+)*([A-Za-z_$][\w$]*)\s*\([^()]*\)\s*\{", re.M), "method"),
]
_DECISIONS = re.compile(r"\b(?:if|for|while|case|catch)\b|&&|\|\||(?<!\?)\?(?![?.])")


def _mask(text):
    return _NON_NEWLINE.sub(" ", text)


def _mask_template(body):
    """Blank template literal text but keep the code inside ${ ... }."""
    out = []
    depth = 0
    i = 0
    while i < len(body):
        ch = body[i]
        if depth == 0:
            if body.startswith("${", i):
                out.append("${")
                depth = 1
                i += 2
                continue
            out.append(ch if ch == "\n" else " ")
        else:
            depth += (ch == "{") - (ch == "}")
            out.append(ch)
        i += 1
    return "".join(out)


def _string_end(src, start):
    quote = src[start]
    j = start + 1
    while j < len(src):
        ch = src[j]
        if ch == "\\":
            j += 2
            continue
        if ch == quote:
            return j + 1, True
        if ch == "\n" and quote != "`":
            break
        j += 1
    return min(j, len(src)), False


def strip_source(src):
    """Blank out comments and string contents, keeping offsets and newlines."""
    out = []
    i, n = 0, len(src)
    while i < n:
        m = _SPECIAL.search(src, i)
        if not m:
            out.append(src[i:])
            break
        out.append(src[i:m.start()])
        i = m.start()
        c = src[i]
        two = src[i:i + 2]
        if two == "//":
            j = src.find("\n", i)
            j = n if j == -1 else j
            out.append(_mask(src[i:j]))
            i = j
        elif two == "/*":
            j = src.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append(_mask(src[i:j]))
            i = j
        elif c == "/":
            out.append(c)
            i += 1
        else:
            j, closed = _string_end(src, i)
            if not closed and c != "`":
                out.append(c)  # e.g. the apostrophe in JSX text
                i += 1
                continue
            seg = src[i:j]
            if closed:
                inner = _mask_template(seg[1:-1]) if c == "`" else _mask(seg[1:-1])
                out.append(c + inner + c)
            else:
                out.append(_mask(seg))
            i = j
    return "".join(out)


def _match(code, start, opener, closer):
    depth = 0
    for k in range(start, len(code)):
        ch = code[k]
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return k
    return -1


def _skip_space(code, k):
    while k < len(code) and code[k].isspace():
        k += 1
    return k


def _functions(code):
    seen = set()
    found = []
    for rx, kind in _PATTERNS:
        for m in rx.finditer(code):
            name = m.group(1) if m.lastindex else "(anonymous)"
            if kind == "method":
                if name in _KEYWORDS:
                    continue
                body = m.end() - 1
            elif kind == "arrow":
                body = _skip_space(code, m.end())
            else:
                paren = code.find("(", m.end())
                if paren == -1:
                    continue
                close = _match(code, paren, "(", ")")
                if close == -1:
                    continue
                body = _skip_space(code, close + 1)
            if body >= len(code) or code[body] != "{" or body in seen:
                continue
            seen.add(body)
            end = _match(code, body, "{", "}")
            if end != -1:
                found.append((name, m.start(), body, end))
    return found


def check(f, limits: Limits) -> list[Finding]:
    skeleton = strip_source(f.text)
    starts = [0] + [i + 1 for i, ch in enumerate(f.text) if ch == "\n"]

    def line_of(offset):
        return bisect.bisect_right(starts, offset)

    out = []
    for name, start, body, end in _functions(skeleton):
        label = "anonymous function" if name == "(anonymous)" else f"{name}()"
        length = line_of(end) - line_of(start) + 1
        if length > limits.max_function_lines:
            out.append(Finding(f.path, line_of(start), "long-function",
                               f"{label} is {length} lines (limit {limits.max_function_lines})"))
        score = 1 + len(_DECISIONS.findall(skeleton, body, end))
        if score > limits.max_complexity:
            out.append(Finding(f.path, line_of(start), "complexity",
                               f"{label} has complexity about {score} (limit {limits.max_complexity})"))

    out.extend(_unused_imports(f, skeleton, line_of))

    for m in re.finditer(r"\beval\s*\(", skeleton):
        out.append(Finding(f.path, line_of(m.start()), "eval-call", "call to eval()", "medium"))
    for m in re.finditer(r"\bcatch\s*(?:\([^)]*\))?\s*\{\s*\}", f.text):
        out.append(Finding(f.path, line_of(m.start()), "empty-catch", "empty catch block", "medium"))

    out.extend(_counted(f.path, skeleton, line_of, r"\bvar\s+[A-Za-z_$\[{]", "use-var",
                        "var used {n} {times}", 1))
    out.extend(_counted(f.path, skeleton, line_of, r"(?<![=!<>])(?:==|!=)(?!=)(?!\s*null\b)", "loose-equality",
                        "== or != used {n} {times}", 1))
    out.extend(_counted(f.path, skeleton, line_of, r"\bconsole\.log\s*\(", "console-log",
                        "console.log called {n} {times}", 5))
    return out


def _counted(path, code, line_of, pattern, rule, template, minimum):
    hits = list(re.finditer(pattern, code))
    if len(hits) < minimum:
        return []
    return [Finding(path, line_of(hits[0].start()), rule, template.format(n=len(hits), times="time" if len(hits) == 1 else "times"))]


_IMPORT_FORMS = [
    re.compile(r"\bimport\s+([A-Za-z_$][\w$]*)\s*(?:,\s*\{([^}]*)\})?\s*from\b"),
    re.compile(r"\bimport\s*\{([^}]*)\}\s*from\b"),
    re.compile(r"\bimport\s*\*\s*as\s+([A-Za-z_$][\w$]*)\s*from\b"),
    re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\("),
    re.compile(r"\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\s*\("),
]


def _unused_imports(f, skeleton, line_of):
    names = []  # (name, offset)
    for rx in _IMPORT_FORMS:
        for m in rx.finditer(skeleton):
            for group in m.groups():
                if not group:
                    continue
                for part in group.split(","):
                    part = part.strip()
                    if not part:
                        continue
                    part = re.split(r"\s+as\s+|:", part)[-1]
                    part = part.split("=")[0].strip()
                    if re.fullmatch(r"[A-Za-z_$][\w$]*", part):
                        names.append((part, m.start()))

    out = []
    seen = set()
    for name, offset in names:
        if name in seen or (name == "React" and f.path.endswith(".jsx")):
            continue
        seen.add(name)
        uses = len(re.findall(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])", skeleton))
        uses += len(re.findall(r"</?" + re.escape(name) + r"(?![\w$])", f.text))
        if uses <= 1:
            out.append(Finding(f.path, line_of(offset), "unused-import", f"'{name}' imported but never used"))
    return out