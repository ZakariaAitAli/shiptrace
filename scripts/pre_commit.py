#!/usr/bin/env -S python3 -I
"""pre-commit hook: fast, deterministic checks on staged content.

Paths, secrets, migrations and style read the index, not the working tree. The lockfile and import
checks need a whole project, so they read the working tree. Any check that cannot run blocks the
commit. Slower gates live in scripts/verify.sh.
"""

import re
import shutil
import subprocess
import sys
import tempfile
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath

TOOLS = Path(__file__).resolve().parents[1]
TIMEOUT_SECONDS = 60
MIGRATIONS = "persistence/migrations/versions/"
FORBIDDEN_GLOBS = (".env", ".env.*", "*.pem", "*.key", "*.tfstate*", "*.tfvars")
ALLOWED_NAMES = {".env.example"}
SECRET_PATTERNS = (
    r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
    r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"\bst1_[A-Za-z0-9_-]{40,}\b",
    r"postgres(ql)?(\+\w+)?://[^:\s/@]+:(?!\{|\$|<)[^@\s]+@",
)


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=check
    )


def staged_files() -> list[tuple[str, str]]:
    output = git("diff", "--cached", "--name-status", "--no-renames", "-z").stdout
    fields = output.split("\0")
    return list(zip(fields[0::2], fields[1::2], strict=False))[: len(fields) // 2]


def forbidden_paths(files: list[tuple[str, str]]) -> list[str]:
    found = []
    for status, path in files:
        name = PurePosixPath(path).name
        forbidden = any(fnmatch(name, pattern) for pattern in FORBIDDEN_GLOBS)
        if status != "D" and name not in ALLOWED_NAMES and forbidden:
            found.append(f"{path}: must not be committed")
    return found


def secrets(_: list[tuple[str, str]]) -> list[str]:
    diff = git("diff", "--cached", "-U0", "--no-color", "--no-ext-diff", "--text").stdout
    found, current = [], "?"
    for line in diff.splitlines():
        if line.startswith("+++ "):
            current = line.removeprefix("+++ b/")
        elif line.startswith("+") and any(re.search(p, line) for p in SECRET_PATTERNS):
            found.append(f"{current}: an added line looks like a secret")  # Never echo the line.
    return found


def applied_migrations(files: list[tuple[str, str]]) -> list[str]:
    if git("rev-parse", "--verify", "-q", "HEAD", check=False).returncode != 0:
        return []
    return [
        f"{path}: an applied migration is immutable, add a new one"
        for status, path in files
        if status in {"M", "D"} and MIGRATIONS in path and path.endswith(".py")
    ]


def tool(*command: str, cwd: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["uv", "run", "--frozen", "--project", str(TOOLS), *command],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
        check=False,
    )


def python_style(files: list[tuple[str, str]]) -> list[str]:
    paths = [p for s, p in files if s != "D" and p.endswith(".py") and not p.startswith(".claude/")]
    if not paths:
        return []
    with tempfile.TemporaryDirectory() as directory:
        # Ruff runs from here and finds this copy, so per-file rules match the exported paths.
        shutil.copy(TOOLS / "pyproject.toml", directory)
        for path in paths:  # Check what will be committed, not what is on disk.
            target = Path(directory, path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(git("show", f":{path}").stdout)
        found = []
        for label, args in (
            ("ruff format", ("format", "--check", ".")),  # Never --diff: it would print lines.
            ("ruff check", ("check", "--no-cache", "--output-format=concise", ".")),
        ):
            result = tool("ruff", *args, cwd=directory)
            if result.returncode != 0:
                found.append(f"{label} failed:\n{(result.stdout + result.stderr)[-1500:]}")
    return found


def lockfile(files: list[tuple[str, str]]) -> list[str]:
    if not {"pyproject.toml", "uv.lock"} & {path for _, path in files}:
        return []
    root = Path(git("rev-parse", "--show-toplevel").stdout.strip())
    if not (root / "uv.lock").exists():
        return ["uv.lock is missing"]
    result = subprocess.run(
        ["uv", "lock", "--check", "--project", str(root)],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
        check=False,
    )
    return [] if result.returncode == 0 else ["uv.lock is stale: run uv lock"]


def boundaries(files: list[tuple[str, str]]) -> list[str]:
    if not any(path.startswith("src/") for _, path in files):
        return []
    root = git("rev-parse", "--show-toplevel").stdout.strip()
    result = tool("lint-imports", cwd=root)
    return [] if result.returncode == 0 else [f"import boundaries:\n{result.stdout[-1200:]}"]


CHECKS = (forbidden_paths, secrets, applied_migrations, python_style, lockfile, boundaries)


def run_checks(files: list[tuple[str, str]]) -> list[str]:
    problems: list[str] = []
    for check in CHECKS:
        found = check(files)
        problems.extend(found)
        if check is secrets and found:
            return problems  # Later tools may quote the offending line, so none of them run.
    return problems


def main() -> int:
    if shutil.which("uv") is None:
        print("pre-commit: uv is not on PATH, so checks cannot run", file=sys.stderr)
        return 1
    try:
        files = staged_files()
        problems = run_checks(files) if files else []
    except (OSError, subprocess.SubprocessError) as error:
        print(f"pre-commit: a check could not run ({type(error).__name__})", file=sys.stderr)
        return 1
    for problem in problems:
        print(f"pre-commit: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
