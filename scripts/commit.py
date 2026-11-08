#!/usr/bin/python3 -I
"""Makes one signed commit of the named paths. The only way Claude Code commits.

    scripts/commit.py "<type>(<scope>): <description>" <path>...

It runs outside the sandbox, after approval of each run, so it trusts nothing the sandbox can
write. The repository is pinned to this project's `.git`, which sandboxed code cannot write, so a
planted `.git/commondir` or configuration cannot redirect git. The environment is rebuilt from an
allowlist, so git and its hooks see no inherited GIT_* override. The message reaches git on stdin as
data, and paths follow `--`. Hooks, signing and identity come from the owner's configuration.

Exit codes: 0 committed with a good signature, 1 refused, 2 usage, 3 committed but the signature did
not verify, which needs the owner.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GIT_DIR = ROOT / ".git"
PASSED_THROUGH = (
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TERM",
    "TZ",
    "GNUPGHOME",
    "GPG_TTY",
    "XDG_RUNTIME_DIR",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "DBUS_SESSION_BUS_ADDRESS",
)
# Directories the sandbox can write, so PATH entries in them are dropped. Not used for files.
WRITABLE_ROOTS = (
    ROOT,
    Path(tempfile.gettempdir()),
    Path("/tmp"),  # noqa: S108
    Path("/var/tmp"),  # noqa: S108
    Path("/dev/shm"),  # noqa: S108
)
TIMEOUT_SECONDS = 300


def trusted_path(value: str) -> str:
    """Keeps PATH entries outside the project and temporary directories."""
    kept = []
    for entry in value.split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            continue
        resolved = Path(os.path.realpath(entry))
        if not any(resolved.is_relative_to(os.path.realpath(root)) for root in WRITABLE_ROOTS):
            kept.append(entry)
    return os.pathsep.join(kept)


def environment() -> dict[str, str]:
    env = {name: os.environ[name] for name in PASSED_THROUGH if name in os.environ}
    env["PATH"] = trusted_path(os.environ.get("PATH", ""))
    env.update(
        GIT_DIR=str(GIT_DIR),
        GIT_COMMON_DIR=str(GIT_DIR),
        GIT_WORK_TREE=str(ROOT),
        UV_NO_SYNC="1",
        UV_NO_CONFIG="1",
    )
    return env


def main(args: list[str]) -> int:
    if len(args) < 2 or not args[0].strip():
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    message, paths = args[0], args[1:]
    if GIT_DIR.is_symlink() or not GIT_DIR.is_dir():
        print("commit: .git must be a real directory", file=sys.stderr)
        return 1
    if os.path.lexists(GIT_DIR / "commondir"):
        print(
            "commit: .git/commondir exists and would redirect git; the owner must check it",
            file=sys.stderr,
        )
        return 1
    env = environment()
    git_binary = shutil.which("git", path=env["PATH"])
    if git_binary is None:
        print("commit: git is not on a trusted PATH entry", file=sys.stderr)
        return 1

    def git(*command: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [git_binary, *command],
            cwd=ROOT,
            env=env,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
            check=False,
        )

    if git("config", "--get", "commit.gpgsign").stdout.strip() != "true":
        print("commit: commit.gpgsign must be true; signing is never skipped", file=sys.stderr)
        return 1
    added = git("add", "--", *paths)
    if added.returncode != 0:
        print(f"commit: git add failed:\n{added.stderr}", file=sys.stderr)
        return 1

    def staged_names(*pathspec: str) -> set[str]:
        return set(git("diff", "--cached", "--name-only", "-z", *pathspec).stdout.split("\0")) - {
            ""
        }

    staged = staged_names()
    if extra := sorted(staged - staged_names("--", *paths)):
        print(
            f"commit: other changes are staged, so the owner must review: {extra}", file=sys.stderr
        )
        return 1
    if not staged:
        print("commit: nothing to commit for those paths", file=sys.stderr)
        return 1
    committed = git("commit", "--file=-", stdin=message)
    sys.stdout.write(committed.stdout)
    sys.stderr.write(committed.stderr)
    if committed.returncode != 0:
        print("commit: refused; the named paths stay staged for a retry", file=sys.stderr)
        return 1
    print(git("log", "-1", "--show-signature").stdout)
    status = git("log", "-1", "--format=%G?").stdout.strip()
    if status != "G":
        print(
            f"commit: committed, but the signature did not verify ({status}); stop", file=sys.stderr
        )
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
