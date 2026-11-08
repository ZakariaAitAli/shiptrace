#!/usr/bin/env python3
"""Proves each gate can fail, and fails for the right reason.

Breaks a throwaway clone one way at a time. A violation counts as caught only when the gate exits 1
and prints the expected marker, so an unrelated failure or an unreachable Docker never counts.
Slow, so it is not part of scripts/verify.sh. Run it before a phase gate.
"""

import json
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE_TIMEOUT_SECONDS = 300
READINESS = "src/shiptrace/application/readiness.py"
HEALTH = "src/shiptrace/api/health.py"
SCHEMA = "src/shiptrace/persistence/schema.py"
MIGRATION = "src/shiptrace/persistence/migrations/versions/0001_runtime_grants.py"
UV = ("uv", "run", "--frozen")
PRECOMMIT = ("python3", "-I", "scripts/pre_commit.py")
CHECK_REPO = ("python3", "-I", "scripts/check_repo.py")
FAST = ("scripts/verify.sh", "--fast")
Breaks = Callable[[Path], None]


def replace(path: str, old: str, new: str) -> Breaks:
    def apply(clone: Path) -> None:
        target = clone / path
        text = target.read_text()
        if old not in text:
            raise SystemExit(f"violation no longer applies: {path}: {old!r}")
        target.write_text(text.replace(old, new, 1))

    return apply


def append(path: str, text: str) -> Breaks:
    def apply(clone: Path) -> None:
        with (clone / path).open("a") as handle:
            handle.write(text)

    return apply


def settings_change(change: Callable[[dict], None]) -> Breaks:
    def apply(clone: Path) -> None:
        path = clone / ".claude/settings.json"
        settings = json.loads(path.read_text())
        change(settings)
        path.write_text(json.dumps(settings))

    return apply


def staged(breaks: Breaks, *ignored_paths: str) -> Breaks:
    def apply(clone: Path) -> None:
        breaks(clone)
        subprocess.run(["git", "add", "-A"], cwd=clone, check=True)
        if ignored_paths:
            subprocess.run(["git", "add", "-f", *ignored_paths], cwd=clone, check=True)

    return apply


def create(path: str, text: str) -> Breaks:
    return lambda clone: (clone / path).write_text(text) and None


def delete(path: str) -> Breaks:
    return lambda clone: (clone / path).unlink()


def unsigned_commit(clone: Path) -> None:
    def git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=clone, check=True, capture_output=True, text=True
        ).stdout.strip()

    tree = git("rev-parse", "HEAD^{tree}")
    commit = git("commit-tree", tree, "-p", "HEAD", "-m", "chore(repo): unsigned probe")
    git("update-ref", "HEAD", commit)


@dataclass(frozen=True)
class Violation:
    label: str
    breaks: Breaks
    gate: tuple[str, ...]
    marker: str


OUTAGE_ONLY = """        except OperationalError:
            return expected_schema().head
        except SQLAlchemyError as error:"""


def outage_reported_as_ready(clone: Path) -> None:
    """Only connection failures, so the unmigrated check still passes and the outage step runs."""
    replace(SCHEMA, "        except SQLAlchemyError as error:", OUTAGE_ONLY)(clone)
    replace(
        SCHEMA,
        "from sqlalchemy.exc import SQLAlchemyError",
        "from sqlalchemy.exc import OperationalError, SQLAlchemyError",
    )(clone)


VIOLATIONS = (
    Violation(
        "formatting",
        replace(READINESS, "import threading", "import   threading"),
        (*UV, "ruff", "format", "--check", "."),
        "would be reformatted",
    ),
    Violation("lint", append(READINESS, "\nimport os\n"), (*UV, "ruff", "check", "."), "F401"),
    Violation(
        "static security rule",
        append(READINESS, "\n\ndef run(x: str) -> None:\n    eval(x)\n"),
        (*UV, "ruff", "check", "."),
        "S307",
    ),
    Violation(
        "type error",
        replace(HEALTH, 'return {"status": "ok"}', 'return {"status": 1}'),
        (*UV, "mypy"),
        "error:",
    ),
    Violation(
        "layer: api to sqlalchemy",
        append(HEALTH, "\nimport sqlalchemy  # noqa\n"),
        (*UV, "lint-imports"),
        "API does not touch database libraries BROKEN",
    ),
    Violation(
        "layer: domain to fastapi",
        append("src/shiptrace/domain/__init__.py", "import fastapi  # noqa\n"),
        (*UV, "lint-imports"),
        "Domain and application stay framework-free BROKEN",
    ),
    Violation(
        "layer: domain to application",
        append(
            "src/shiptrace/domain/__init__.py", "import shiptrace.application.readiness  # noqa\n"
        ),
        (*UV, "lint-imports"),
        "Layers BROKEN",
    ),
    Violation(
        "a stray .importlinter cannot disable contracts",
        lambda clone: (
            create(".importlinter", "[importlinter]\nroot_package = shiptrace\n")(clone),
            append(HEALTH, "\nimport sqlalchemy  # noqa\n")(clone),
        )[0],
        (*UV, "lint-imports", "--config", "pyproject.toml"),
        "API does not touch database libraries BROKEN",
    ),
    Violation(
        "a stray mypy.ini cannot disable checks",
        lambda clone: (
            create("mypy.ini", "[mypy]\nignore_errors = True\n")(clone),
            replace(HEALTH, 'return {"status": "ok"}', 'return {"status": 1}')(clone),
        )[0],
        (*UV, "mypy", "--config-file", "pyproject.toml"),
        "error:",
    ),
    Violation(
        "unit test",
        replace(
            READINESS,
            "    except ProbeError:\n        return False",
            "    except ProbeError:\n        return True",
        ),
        (*UV, "pytest", "tests/unit", "-q", "-x"),
        "FAILED tests/unit/",
    ),
    Violation(
        "integration test",
        replace(
            MIGRATION, 'op.execute("GRANT SELECT ON alembic_version TO shiptrace_app")', "pass"
        ),
        (*UV, "pytest", "tests/integration", "-q", "-x"),
        "FAILED tests/integration/test_database_init.py::test_upgrade_downgrade_round_trip",
    ),
    Violation(
        "stale lockfile",
        replace("pyproject.toml", '"uvicorn>=0.54.0,<0.55"', '"uvicorn>=0.53.0,<0.55"'),
        ("uv", "lock", "--check"),
        "needs to be updated",
    ),
    Violation(
        "broken doc link",
        append("README.md", "\n[x](docs/missing.md)\n"),
        CHECK_REPO,
        "broken link",
    ),
    Violation(
        "unevidenced ASVS Pass",
        replace(
            "docs/security/ASVS_ASSESSMENT.md",
            "hostile-text test | Planned |",
            "hostile-text test | Pass |",
        ),
        CHECK_REPO,
        "without linked evidence",
    ),
    Violation(
        "reviewer given an edit tool",
        replace(
            ".claude/agents/test-reviewer.md",
            "tools: Read, Grep, Glob, Bash",
            "tools: Read, Grep, Glob, Bash, Write",
        ),
        CHECK_REPO,
        "must not have edit",
    ),
    Violation(
        "sandbox removed",
        settings_change(lambda s: s.pop("sandbox")),
        CHECK_REPO,
        "sandbox configuration is required",
    ),
    Violation(
        "sandbox fails open",
        settings_change(lambda s: s["sandbox"].update(failIfUnavailable=False)),
        CHECK_REPO,
        "must fail closed",
    ),
    Violation(
        "unsandboxed retries allowed",
        settings_change(lambda s: s["sandbox"].update(allowUnsandboxedCommands=True)),
        CHECK_REPO,
        "must fail closed",
    ),
    Violation(
        "signing keys readable",
        settings_change(lambda s: s["sandbox"]["filesystem"]["denyRead"].remove("~/.gnupg")),
        CHECK_REPO,
        "denyRead is missing",
    ),
    Violation(
        "scripts writable",
        settings_change(lambda s: s["sandbox"]["filesystem"]["denyWrite"].remove("scripts")),
        CHECK_REPO,
        "denyWrite is missing",
    ),
    Violation(
        "network widened",
        settings_change(lambda s: s["sandbox"]["network"]["allowedDomains"].append("github.com")),
        CHECK_REPO,
        "network domains are not permitted",
    ),
    Violation(
        "new sandbox exclusion",
        settings_change(lambda s: s["sandbox"]["excludedCommands"].append("docker *")),
        CHECK_REPO,
        "exclusions are not permitted",
    ),
    Violation(
        "exclusion auto-allowed",
        settings_change(lambda s: s["permissions"]["allow"].append("Bash(scripts/commit.py *)")),
        CHECK_REPO,
        "must not be auto-allowed",
    ),
    Violation(
        "gate removed from verify.sh",
        replace("scripts/verify.sh", "uv run --frozen mypy", "true"),
        CHECK_REPO,
        "verify.sh is missing a gate",
    ),
    Violation(
        "weakened guard hook",
        replace(
            ".claude/hooks/guard_bash.py",
            'if subcommand == "push" or (',
            'if subcommand == "pushx" or (',
        ),
        ("python3", "-I", ".claude/hooks/tests/test_hooks.py"),
        "FAIL: test_denied",
    ),
    Violation(
        "unsigned commit",
        unsigned_commit,
        ("python3", "-I", "scripts/check_history.py"),
        "signature status N",
    ),
    Violation(
        "wheel without migrations",
        delete("src/shiptrace/persistence/migrations/script.py.mako"),
        FAST,
        "==> built wheel ships the migrations",
    ),
    Violation(
        "pre-commit: secret file",
        staged(create(".env", "A=1\n"), ".env"),
        PRECOMMIT,
        "must not be committed",
    ),
    Violation(
        "pre-commit: unformatted", staged(create("x.py", "A   =  1\n")), PRECOMMIT, "ruff format"
    ),
    Violation(
        "pre-commit: applied migration",
        staged(append(MIGRATION, "\n# edited\n")),
        PRECOMMIT,
        "applied migration",
    ),
    Violation(
        "pre-commit: stale lockfile",
        staged(replace("pyproject.toml", '"uvicorn>=0.54.0,<0.55"', '"uvicorn>=0.53.0,<0.55"')),
        PRECOMMIT,
        "uv.lock is stale",
    ),
    Violation(
        "smoke: outage reported as ready",
        outage_reported_as_ready,
        ("scripts/smoke.sh",),
        "FAILED during: interrupt the database",
    ),
    Violation(
        "verify.sh stops at a failure",
        append(READINESS, "\nimport os\n"),
        FAST,
        "would be reformatted",
    ),
)


def run(command: tuple[str, ...], cwd: Path) -> tuple[int, str]:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=GATE_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return -1, "timed out"
    return result.returncode, result.stdout + result.stderr


def main() -> int:
    with tempfile.TemporaryDirectory() as directory:
        clone = Path(directory) / "clone"
        subprocess.run(["git", "clone", "-q", str(ROOT), str(clone)], check=True)
        subprocess.run(["uv", "sync", "--locked", "-q"], cwd=clone, check=True)
        baseline, output = run(("scripts/verify.sh",), clone)
        print(f"baseline scripts/verify.sh: exit {baseline}")
        if baseline != 0:
            print(output[-2000:])
            return 1
        head = run(("git", "rev-parse", "HEAD"), clone)[1].strip()
        missed = 0
        for violation in VIOLATIONS:
            for command in (
                ("git", "reset", "-q", "--hard", head),
                ("git", "clean", "-qfdx", "-e", ".venv"),
            ):
                subprocess.run(command, cwd=clone, check=True)
            violation.breaks(clone)
            code, output = run(violation.gate, clone)
            caught = code == 1 and violation.marker in output
            missed += not caught
            print(f"{'caught' if caught else 'MISSED'}  exit={code:<3} {violation.label}")
            if not caught:
                print("    " + output[-400:].replace("\n", "\n    "))
    print(f"violations={len(VIOLATIONS)} missed={missed}")
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main())
