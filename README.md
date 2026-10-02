# repolens

A small command line tool that looks through a project folder and tells you how big it is, which functions have grown out of hand, and whether anyone committed a password.

It only uses the Python standard library, works offline, and reads files without running or importing any of your code.

## Install

```
pip install repolens
```

Or from a clone:

```
git clone https://github.com/Prabhatyadav92/repolens
cd repolens
pip install .
```

Python 3.9 or newer.

## Use

```
repolens .                 # summary and findings
repolens secrets .         # only secrets, exit code 1 if any are found
repolens report .          # write repolens-report.md
repolens rules             # list every check
```

Example:

```
$ repolens src/
Scanning /home/me/newspulse/src

Languages
  JavaScript  41 files  7,204 lines
  Python      22 files  3,118 lines

  Total       63 files  10,322 lines

Secrets (1)
  config.js:7  aws-access-key  AWS access key: AKIA********

Findings (9)
  server.js:10  long-function   anonymous function is 112 lines (limit 60)
  ...
```

Useful options:

| Option | What it does |
| --- | --- |
| `-x GLOB`, `--exclude GLOB` | Skip matching files or folders. Repeatable. |
| `--max-function-lines N` | Length before `long-function` fires (default 60). |
| `--max-complexity N` | Branch count before `complexity` fires (default 15). |
| `--fail-on LEVEL` | Exit 1 if something at `low`, `medium` or `high` is found. Handy in CI. |
| `--all` | Print every finding instead of the first 20. |

Files matched by `.gitignore` are skipped, along with `node_modules`, virtualenvs and build folders. To silence a single line, put `repolens: ignore` in a comment on it.

## What it checks

- **Python** (via `ast`): long or complex functions, too many parameters, mutable default arguments, bare `except`, `eval`/`exec`, unused imports.
- **JavaScript** (regex, no parser): long or complex functions, unused imports and requires, `var`, loose equality, empty `catch`, `eval`, leftover `console.log`.
- **Any text file**: TODO / FIXME / HACK / XXX in comments.
- **Secrets**: private keys, AWS, GitHub, Slack, Google and Stripe keys, JWTs, database URLs with passwords, `password = "..."` style assignments, and `.env` files. Secret values are always masked in output.

## Limits

The JavaScript checks are approximate. Regex literals and unusual formatting can confuse the function-length counting, and TypeScript is counted but not analyzed. `.gitignore` negation rules (`!pattern`) are ignored. The secret scanner will miss secrets it has no pattern for and will sometimes flag test fixtures; use `repolens: ignore` for those. It is not a replacement for a tool like gitleaks if you need serious coverage.

## Development

```
pip install pytest
pytest
```

## License

MIT, see [LICENSE](LICENSE).
