from repolens import analyze, secrets
from repolens.models import Limits
from repolens.scanner import scan


def make(tmp_path, files):
    for name, content in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return scan(tmp_path)


def rules(findings):
    return {f.rule for f in findings}


def test_scanner_counts_and_ignores(tmp_path):
    result = make(tmp_path, {
        "a.py": "x = 1\n\ny = 2\n",
        "node_modules/m.js": "var a;",
        "skip.log": "hello",
        ".gitignore": "*.log\n",
    })
    assert result.languages()["Python"] == (1, 2)
    assert "node_modules/m.js" not in [f.path for f in result.files]
    assert "skip.log" not in [f.path for f in result.files]


def test_python_checks(tmp_path):
    code = (
        "import os\nimport json\n\n"
        "def f(a, items=[]):\n    try:\n        return json.dumps(a)\n    except:\n        return eval('1')\n"
    )
    result = make(tmp_path, {"m.py": code})
    found = rules(analyze.run(result.files, Limits()))
    assert {"unused-import", "mutable-default", "bare-except", "eval-call"} <= found
    names = [f.message for f in analyze.run(result.files, Limits()) if f.rule == "unused-import"]
    assert names == ["'os' imported but never used"]


def test_python_limits(tmp_path):
    body = "\n".join(f"    if x == {i}:\n        return {i}" for i in range(6))
    result = make(tmp_path, {"m.py": f"def f(x):\n{body}\n"})
    found = rules(analyze.run(result.files, Limits(max_function_lines=5, max_complexity=3)))
    assert {"long-function", "complexity"} <= found
    assert not rules(analyze.run(result.files, Limits()))


def test_python_init_reexports_are_not_flagged(tmp_path):
    result = make(tmp_path, {"pkg/__init__.py": "from .core import thing\n"})
    assert not analyze.run(result.files, Limits())


def test_js_checks(tmp_path):
    code = (
        "const fs = require('fs');\nconst { a, b } = require('x');\nvar n = 1;\n"
        "function go(v) {\n  if (v == 2) { return a; }\n  try { run(); } catch (e) {}\n}\n"
    )
    result = make(tmp_path, {"m.js": code})
    found = analyze.run(result.files, Limits())
    assert {"use-var", "loose-equality", "empty-catch"} <= rules(found)
    unused = {f.message for f in found if f.rule == "unused-import"}
    assert unused == {"'fs' imported but never used", "'b' imported but never used"}


def test_js_function_length_ignores_braces_in_strings(tmp_path):
    code = "function f() {\n  const s = '}}}';\n  return s;\n}\n" + "x = 1;\n" * 10
    result = make(tmp_path, {"m.js": code})
    assert "long-function" not in rules(analyze.run(result.files, Limits(max_function_lines=5)))


def test_js_long_function(tmp_path):
    body = "  work();\n" * 8
    result = make(tmp_path, {"m.js": f"const go = () => {{\n{body}}};\n"})
    found = analyze.run(result.files, Limits(max_function_lines=5))
    assert [f.rule for f in found if f.rule == "long-function"] == ["long-function"]


def test_todo_marker(tmp_path):
    result = make(tmp_path, {"m.py": "x = 1  # TO" + "DO: tidy up\ny = 'TO" + "DO'\n"})
    found = [f for f in analyze.run(result.files, Limits()) if f.rule == "todo"]
    assert len(found) == 1 and found[0].line == 1


def test_secrets_are_found_and_masked(tmp_path):
    key = "AKIA" + "QWERTY1234ZXCVBN"
    result = make(tmp_path, {
        "cfg.py": f'KEY = "{key}"\npassword = "Sup3rS3cret!"\n',
        ".env": "API_TOKEN=abcd1234efgh5678\n",
    })
    found = secrets.scan(result)
    assert {"aws-access-key", "hardcoded-secret", "env-file"} <= rules(found)
    assert all(key not in f.message and "Sup3rS3cret" not in f.message for f in found)


def test_secret_false_positives(tmp_path):
    result = make(tmp_path, {
        "a.py": (
            'password = "changeme123"\n'
            'token = "Authorization"\n'
            'secret = os.environ["SECRET_VALUE"]\n'
            'k = "AKIAIOSFODNN7EXAMPLE"\n'
        ),
        ".env.example": "API_TOKEN=abcd1234efgh5678\n",
    })
    assert secrets.scan(result) == []


def test_ignore_marker(tmp_path):
    line = 'password = "Sup3rS3cret!"  # repolens: ignore\n'
    assert secrets.scan(make(tmp_path, {"a.py": line})) == []


def test_gitignored_env_is_not_reported(tmp_path):
    result = make(tmp_path, {".env": "API_TOKEN=abcd1234efgh5678\n", ".gitignore": ".env\n"})
    assert secrets.scan(result) == []


def test_js_template_literal_counts_as_use(tmp_path):
    result = make(tmp_path, {"m.js": "const name = require('name');\nconsole.log(`hi ${name}`);\n"})
    assert "unused-import" not in rules(analyze.run(result.files, Limits()))


def test_jsx_apostrophe_does_not_hide_a_component(tmp_path):
    jsx = (
        "import { Link } from 'react-router-dom';\n"
        "export default function Login() {\n"
        "  return <p>Don't have an account? <Link to=\"/register\">Sign up</Link></p>;\n"
        "}\n"
    )
    result = make(tmp_path, {"Login.jsx": jsx})
    assert "unused-import" not in rules(analyze.run(result.files, Limits()))


def test_repeated_demo_passwords_are_collapsed(tmp_path):
    seed = "".join(f"u{i} = {{ password: 'Sup3rS3cret{i}!' }}\n" for i in range(8))  # repolens: ignore
    found = secrets.scan(make(tmp_path, {"seed.js": seed}))
    assert len(found) == 1 and "7 more" in found[0].message