# repolens

[![tests](https://github.com/Prabhatyadav92/repolens/actions/workflows/ci.yml/badge.svg)](https://github.com/Prabhatyadav92/repolens/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/repolens-scan)](https://pypi.org/project/repolens-scan/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A small command line tool that looks through a project folder and tells you how big it is, which functions have grown out of hand, and whether anyone committed a password.

It only uses the Python standard library, works offline, and reads files without running or importing any of your code.

## Install

```
pip install repolens-scan
```

The package is called `repolens-scan` on PyPI, but the command it installs is `repolens`.

Or from a clone:

```
git clone https://github.com/Prabhatyadav92/repolens.git
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
repolens --version
```

If `repolens` is not found after installing, either your pip scripts folder is not on `PATH` or your virtual environment is not active. `python -m repolens .` works either way.

## Example

This is a real run on a small MERN project (React frontend, Express backend):

```
$ repolens ~/projects/skillswap
Scanning /Users/me/projects/skillswap

Languages
  JavaScript  54 files  2,750 lines
  Markdown     1 file     150 lines
  JSON         2 files     54 lines
  CSS          1 file      31 lines
  Other        3 files     18 lines
  HTML         1 file      14 lines

  Total       62 files  3,017 lines

Project
  dependency files: backend/package.json, frontend/package.json
  not found: LICENSE, tests
  2 generated/minified files not counted

Secrets (2)
  backend/seed.js:20              hardcoded-secret  value for password: pass******** (and 10 more in this file)
  frontend/src/pages/Login.jsx:9  hardcoded-secret  value for password: pass********

Findings (18)
  backend/controllers/sessionController.js:65  long-function  updateSessionStatus() is 89 lines (limit 60)
  frontend/src/pages/EditProfile.jsx:59        long-function  EditProfile() is 210 lines (limit 60)
  frontend/src/pages/EditProfile.jsx:59        complexity     EditProfile() has complexity about 24 (limit 15)
  ...

18 findings, 2 possible secrets. Run `repolens report` for a file.
```

Secret values are always masked in the output and in the report.

## Options

| Option | What it does |
| --- | --- |
| `-x GLOB`, `--exclude GLOB` | Skip matching files or folders. Repeatable. |
| `--max-function-lines N` | Length before `long-function` fires (default 60). |
| `--max-complexity N` | Branch count before `complexity` fires (default 15). |
| `--max-args N` | Parameter count before `many-args` fires (default 7). |
| `--fail-on LEVEL` | Exit 1 if something at `low`, `medium` or `high` is found. |
| `--all` | Print every finding instead of the first 20. |
| `-o FILE`, `--output FILE` | Where `report` writes (default `repolens-report.md`). |

Files matched by `.gitignore` are skipped, along with `node_modules`, virtualenvs and build folders. To silence a single line, put `repolens: ignore` in a comment on it.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Finished. For `scan`, this is the result whether or not anything was found, unless `--fail-on` is set. |
| 1 | `secrets` found something, or `--fail-on` matched a finding. |
| 2 | The path is not a directory. |

## Use it in CI

Fail a build if a secret slips