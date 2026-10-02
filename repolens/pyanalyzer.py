from __future__ import annotations

import ast
import re

from .models import Finding, Limits

_WORDS = re.compile(r"[A-Za-z_]\w*")
_BRANCHES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp)


def check(f, limits: Limits) -> list[Finding]:
    try:
        tree = ast.parse(f.text, filename=f.path)
    except SyntaxError as exc:
        return [Finding(f.path, exc.lineno or 1, "syntax-error", f"cannot parse: {exc.msg}", "medium")]
    except (ValueError, RecursionError):
        return []

    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.extend(_check_function(f.path, node, limits))
        elif isinstance(node, ast.ExceptHandler) and node.type is None:
            out.append(Finding(f.path, node.lineno, "bare-except", "bare 'except:' clause", "medium"))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            out.append(Finding(f.path, node.lineno, "eval-call", f"call to {node.func.id}()", "medium"))
    if not f.path.endswith("__init__.py"):
        out.extend(_unused_imports(f.path, tree))
    return out


def _check_function(path, node, limits):
    found = []
    length = node.end_lineno - node.lineno + 1
    if length > limits.max_function_lines:
        found.append(Finding(path, node.lineno, "long-function",
                             f"{node.name}() is {length} lines (limit {limits.max_function_lines})"))

    score = _complexity(node)
    if score > limits.max_complexity:
        found.append(Finding(path, node.lineno, "complexity",
                             f"{node.name}() has complexity {score} (limit {limits.max_complexity})"))

    a = node.args
    names = [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
    if names and names[0] in ("self", "cls"):
        names = names[1:]
    if len(names) > limits.max_args:
        found.append(Finding(path, node.lineno, "many-args",
                             f"{node.name}() takes {len(names)} parameters (limit {limits.max_args})"))

    defaults = a.defaults + [d for d in a.kw_defaults if d is not None]
    for d in defaults:
        mutable_call = isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id in ("list", "dict", "set")
        if isinstance(d, (ast.List, ast.Dict, ast.Set)) or mutable_call:
            found.append(Finding(path, d.lineno, "mutable-default",
                                 f"{node.name}() uses a mutable default argument", "medium"))
    return found


def _complexity(fn) -> int:
    total = 1
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            continue  # nested definitions are scored on their own
        if isinstance(node, _BRANCHES):
            total += 1
        elif isinstance(node, ast.BoolOp):
            total += len(node.values) - 1
        elif isinstance(node, ast.comprehension):
            total += 1 + len(node.ifs)
        stack.extend(ast.iter_child_nodes(node))
    return total


def _imported_names(tree):
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported[(alias.asname or alias.name).split(".")[0]] = node.lineno
        elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
            for alias in node.names:
                if alias.name != "*":
                    imported[alias.asname or alias.name] = node.lineno
    return imported


def _used_names(tree):
    used = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            used.add(node.id)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) < 80:
            # quoted annotations and __all__ entries
            used.update(_WORDS.findall(node.value))
    return used


def _unused_imports(path, tree):
    used = _used_names(tree)
    imported = _imported_names(tree)
    return [
        Finding(path, line, "unused-import", f"'{name}' imported but never used")
        for name, line in sorted(imported.items(), key=lambda kv: kv[1])
        if name not in used
    ]
