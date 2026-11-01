#!/usr/bin/env python3
"""Proves each gate can fail: breaks a throwaway clone one way at a time and expects a refusal.

Slow, so it is not part of scripts/verify.sh. Run before a phase gate. Exit 0 only if every
deliberate violation was caught and the unbroken clone passed first.
"""

import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE_TIMEOUT_SECONDS = 240
READINESS = "src/shiptrace/application/readiness.py"
HEALTH = "src/shiptrace/api/health.py"
SCHEMA = "src/shiptrace/persistence/schema.py"
MIGRATION = "src/shiptrace/persistence/migrations/versions/0001_runtime_grants.py"
UV = ("uv", "run", "--frozen")
PRECOMMIT = ("python3", "-I", "scripts/pre_commit.py")


def replace(path: str, old: str, new: str) -> Callable[[Path], None]:
    def apply(clone: Path) -> None:
        target = clone / path
        text = target.read_text()
        if old not in text:
            raise SystemExit(f"violation no longer applies: {path}: {old!r}")
        target.write_text(text.replace(old, new, 1))

    return apply


def append(path: str, text: str) -> Callable[[Path], None]:
    def apply(clone: Path) -> None:
        with (clone / path).open("a") as handle:
            handle.write(text)

    return apply


def stage(path: str, text: str) -> Callable[[Path], None]:
    def apply(clone: Path) -> None:
        (clone / path).write_text(text)
        subprocess.run(["git", "add", "-f", path], cwd=clone, check=True)

    return apply


def unsigned_commit(clone: Path) -> None:
    def run(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=clone, check=True, capture_output=True, text=True
        ).stdout.strip()

    tree = run("rev-parse", "HEAD^{tree}")
    commit = run("commit-tree", tree, "-p", "HEAD", "-m", "chore(repo): unsigned probe")
    run("update-ref", "HEAD", commit)


def delete(path: str) -> Callable[[Path], None]:
    return lambda clone: (clone / path).unlink()


@dataclass(frozen=True)
class Violation:
    label: str
    breaks: Callable[[Path], None]
    gate: tuple[str, ...]


VIOLATIONS = (
    Violation(
        "formatting",
        replace(READINESS, "import threading", "import   threading"),
        (*UV, "ruff", "format", "--check", "."),
    ),
    Violation("lint", append(READINESS, "\nimport os\n"), (*UV, "ruff", "check", ".")),
    Violation(
        "static security rule",
        append(READINESS, "\n\ndef run(x: str) -> None:\n    eval(x)  # type: ignore\n"),
        (*UV, "ruff", "check", "."),
    ),
    Violation(
        "type error",
        replace(
            HEALTH, 'return {"status": "ok"}\n\n    @router', 'return {"status": 1}\n\n    @router'
        ),
        (*UV, "mypy"),
    ),
    Violation(
        "layer: api to sqlalchemy",
        append(HEALTH, "\nimport sqlalchemy  # noqa\n"),
        (*UV, "lint-imports"),
    ),
    Violation(
        "layer: domain to fastapi",
        append("src/shiptrace/domain/__init__.py", "import fastapi  # noqa\n"),
        (*UV, "lint-imports"),
    ),
    Violation(
        "layer: application to persistence",
        append(READINESS, "\nimport shiptrace.persistence.engine  # noqa\n"),
        (*UV, "lint-imports"),
    ),
    Violation(
        "unit test",
        replace(
            READINESS,
            "        return False\n    if revision",
            "        return True\n    if revision",
        ),
        (*UV, "pytest", "tests/unit", "-q", "-x"),
    ),
    Violation(
        "integration test",
        replace(
            MIGRATION, 'op.execute("GRANT SELECT ON alembic_version TO shiptrace_app")', "pass"
        ),
        (*UV, "pytest", "tests/integration", "-q", "-x"),
    ),
    Violation(
        "stale lockfile",
        replace("pyproject.toml", '"uvicorn>=0.54.0,<0.55"', '"uvicorn>=0.53.0,<0.55"'),
        ("uv", "lock", "--check"),
    ),
    Violation(
        "broken doc link",
        append("README.md", "\n[x](docs/missing.md)\n"),
        ("python3", "-I", "scripts/check_repo.py"),
    ),
    Violation(
        "unevidenced ASVS Pass",
        replace(
            "docs/security/ASVS_ASSESSMENT.md",
            "hostile-text test | Planned |",
            "hostile-text test | Pass |",
        ),
        ("python3", "-I", "scripts/check_repo.py"),
    ),
    Violation(
        "reviewer given an edit tool",
        replace(
            ".claude/agents/test-reviewer.md",
            "tools: Read, Grep, Glob, Bash",
            "tools: Read, Grep, Glob, Bash, Write",
        ),
        ("python3", "-I", "scripts/check_repo.py"),
    ),
    Violation(
        "weakened guard hook",
        replace(
            ".claude/hooks/guard_bash.py",
            'if subcommand == "push" or (',
            'if subcommand == "pushx" or (',
        ),
        ("python3", "-I", ".claude/hooks/tests/test_hooks.py"),
    ),
    Violation("unsigned commit", unsigned_commit, ("python3", "-I", "scripts/check_history.py")),
    Violation(
        "wheel without migrations",
        delete("src/shiptrace/persistence/migrations/script.py.mako"),
        (
            "bash",
            "-c",
            "d=$(mktemp -d); uv build --wheel -q -o $d && "
            "python3 -I -m zipfile -l $d/*.whl | grep -q script.py.mako",
        ),
    ),
    Violation("pre-commit: staged secret file", stage(".env", "A=1\n"), PRECOMMIT),
    Violation("pre-commit: staged unformatted python", stage("x.py", "A   =  1\n"), PRECOMMIT),
    Violation(
        "pre-commit: edited applied migration", stage(MIGRATION, 'VALUE = "changed"\n'), PRECOMMIT
    ),
    Violation(
        "smoke: outage reported as ready",
        replace(
            READINESS,
            "    except ProbeError:\n        return False",
            "    except ProbeError:\n        return True",
        ),
        ("scripts/smoke.sh",),
    ),
    Violation(
        "whole verify.sh stops on a failure",
        append(READINESS, "\nimport os\n"),
        ("scripts/verify.sh", "--fast"),
    ),
)


def run(command: tuple[str, ...], cwd: Path) -> int:
    try:
        return subprocess.run(
            command, cwd=cwd, capture_output=True, timeout=GATE_TIMEOUT_SECONDS, check=False
        ).returncode
    except subprocess.TimeoutExpired:
        return -1


def fresh_clone(parent: Path) -> Path:
    clone = parent / "clone"
    subprocess.run(["git", "clone", "-q", str(ROOT), str(clone)], check=True)
    subprocess.run(["uv", "sync", "--locked", "-q"], cwd=clone, check=True)
    return clone


def main() -> int:
    with tempfile.TemporaryDirectory() as directory:
        parent = Path(directory)
        clone = fresh_clone(parent)
        baseline = run(("scripts/verify.sh", "--fast"), clone)
        print(f"baseline scripts/verify.sh --fast: exit {baseline}")
        if baseline != 0:
            return 1
        missed = 0
        for violation in VIOLATIONS:
            subprocess.run(["git", "reset", "-q", "--hard", "HEAD"], cwd=clone, check=True)
            subprocess.run(["git", "clean", "-qfdx", "-e", ".venv"], cwd=clone, check=True)
            violation.breaks(clone)
            code = run(violation.gate, clone)
            caught = code not in (0, -1)
            missed += not caught
            print(f"{'caught' if caught else 'MISSED'}  exit={code:<3} {violation.label}")
            if violation.breaks is unsigned_commit:
                shutil.rmtree(clone)
                clone = fresh_clone(parent)
    print(f"violations={len(VIOLATIONS)} missed={missed}")
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main())
