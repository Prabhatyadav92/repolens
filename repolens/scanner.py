from __future__ import annotations

import fnmatch
import os
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

LANGUAGES = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript",
    ".cjs": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript", ".java": "Java",
    ".go": "Go", ".rs": "Rust", ".rb": "Ruby", ".php": "PHP", ".c": "C", ".h": "C",
    ".cpp": "C++", ".cc": "C++", ".hpp": "C++", ".cs": "C#", ".html": "HTML",
    ".css": "CSS", ".scss": "SCSS", ".json": "JSON", ".yml": "YAML", ".yaml": "YAML",
    ".toml": "TOML", ".md": "Markdown", ".sh": "Shell", ".bash": "Shell", ".sql": "SQL",
}
NAMED_FILES = {"Dockerfile": "Docker", "Makefile": "Make"}

SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".next",
    ".idea", ".vscode", "target", "vendor", ".tox", ".mypy_cache", ".pytest_cache",
    "coverage", ".gradle",
}
SKIP_FILES = {"repolens-report.md"}
BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".pdf", ".zip", ".gz", ".tar",
    ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".pyc", ".so", ".dll", ".exe",
    ".class", ".jar",
}
LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock",
    "composer.lock", "Cargo.lock", "go.sum",
}
MANIFESTS = {
    "package.json", "requirements.txt", "pyproject.toml", "setup.py", "Pipfile",
    "pom.xml", "build.gradle", "go.mod", "Cargo.toml", "Gemfile", "composer.json",
}
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs"}
MAX_BYTES = 1_000_000


@dataclass
class FileInfo:
    path: str  # relative to the scan root, always with forward slashes
    language: str
    lines: int
    blank: int
    text: str
    generated: bool = False

    @property
    def loc(self) -> int:
        return self.lines - self.blank


@dataclass
class ScanResult:
    root: Path
    files: list[FileInfo] = field(default_factory=list)
    skipped: int = 0

    @property
    def counted(self) -> list[FileInfo]:
        return [f for f in self.files if not f.generated]

    def languages(self) -> dict[str, tuple[int, int]]:
        totals = defaultdict(lambda: [0, 0])
        for f in self.counted:
            totals[f.language][0] += 1
            totals[f.language][1] += f.loc
        return {k: (v[0], v[1]) for k, v in totals.items()}

    def manifests(self) -> list[str]:
        return sorted(f.path for f in self.files if f.path.rsplit("/", 1)[-1] in MANIFESTS)

    def missing(self) -> list[str]:
        top = [f.path.lower() for f in self.files if "/" not in f.path]
        out = []
        if not any(p.startswith("readme") for p in top):
            out.append("README")
        if not any(p.startswith(("license", "licence", "copying")) for p in top):
            out.append("LICENSE")
        if ".gitignore" not in top:
            out.append(".gitignore")
        if not any(_is_test(f.path) for f in self.files):
            out.append("tests")
        return out


def _is_test(path: str) -> bool:
    parts = path.lower().split("/")
    name = parts[-1]
    if any(p in TEST_DIRS for p in parts[:-1]):
        return True
    return name.startswith("test_") or name.endswith(("_test.py", ".test.js", ".spec.js", ".test.ts", ".spec.ts"))


def _load_ignore(root: Path) -> list[str]:
    gitignore = root / ".gitignore"
    if not gitignore.is_file():
        return []
    patterns = []
    for raw in gitignore.read_text(errors="ignore").splitlines():
        line = raw.strip()
        # negations ("!keep.me") are not supported
        if line and not line.startswith(("#", "!")):
            patterns.append(line)
    return patterns


def _ignored(rel: str, name: str, is_dir: bool, patterns: list[str]) -> bool:
    for pat in patterns:
        if pat.endswith("/"):
            if not is_dir:
                continue
            pat = pat[:-1]
        if pat.startswith("/") or "/" in pat:
            if fnmatch.fnmatch(rel, pat.lstrip("/")):
                return True
        elif fnmatch.fnmatch(name, pat):
            return True
    return False


def scan(root, exclude=()) -> ScanResult:
    root = Path(root).resolve()
    patterns = _load_ignore(root) + list(exclude)
    result = ScanResult(root=root)

    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root)
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS
            and not d.endswith(".egg-info")
            and not _ignored((rel_dir / d).as_posix(), d, True, patterns)
        )
        for name in sorted(filenames):
            rel = (rel_dir / name).as_posix()
            ext = os.path.splitext(name)[1].lower()
            if name in SKIP_FILES or ext in BINARY_EXT or _ignored(rel, name, False, patterns):
                continue
            info = _read(Path(dirpath) / name, rel, name, ext, result)
            if info:
                result.files.append(info)
    return result


def _read(full: Path, rel: str, name: str, ext: str, result: ScanResult):
    try:
        if full.stat().st_size > MAX_BYTES:
            result.skipped += 1
            return None
        data = full.read_bytes()
    except OSError:
        result.skipped += 1
        return None
    if b"\x00" in data[:8192]:
        return None

    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    blank = sum(1 for line in lines if not line.strip())
    language = NAMED_FILES.get(name) or LANGUAGES.get(ext, "Other")
    minified = name.endswith((".min.js", ".min.css", ".map")) or (
        len(lines) > 0 and len(text) / len(lines) > 300
    )
    return FileInfo(rel, language, len(lines), blank, text, generated=name in LOCKFILES or minified)
