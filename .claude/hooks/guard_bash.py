#!/usr/bin/env python3
"""PreToolUse guard for Bash commands. Denies outward, destructive and secret-reading actions.

A guardrail against mistakes, not a security boundary: indirection such as a written script
is out of its reach. Any error while checking blocks the command.
"""

import json
import re
import shlex
import sys

SECRET_PATH = re.compile(
    r"(^|[\s/=\"'~])(\.ssh|\.aws|\.config/gh|\.docker/config\.json|\.netrc|\.pgpass"
    r"|\.claude/\.credentials\.json)(/|$|[\s\"';|&)])"
    r"|\.tfstate"
)
SECRET_ENV_FILE = re.compile(r"(^|[\s/=\"'])\.env(\.(?!example\b)[\w-]+)?($|[\s\"';|&)*])")
BYPASS = re.compile(r"dangerously-skip-permissions|bypassPermissions|dangerouslyDisableSandbox")
PIPE_TO_SHELL = re.compile(r"\b(curl|wget)\b[^|;&]*\|\s*(sudo(\s+-\S+)*\s+)?(ba|z|da)?sh\b")
SUBSTITUTION_TO_SHELL = re.compile(r"\b(ba|z|da)?sh\b[^|;&]*(\$\(|<\(|`)\s*(curl|wget)\b")
SUBSTITUTION = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")

PROTECTED_TARGET = (
    r"(\S*/)?(uv\.lock|actions\.lock|\.claude/settings(\.local)?\.json)"
    r"|\S*\.claude/hooks/\S*|\S*migrations/versions/\S*"
)
SHELL_WRITE = re.compile(rf"(>>?\s*|\btee\s+(-\S+\s+)*)({PROTECTED_TARGET})")
SED_IN_PLACE = re.compile(rf"\bsed\b[^|;&]*\s-i\S*[^|;&]*\s({PROTECTED_TARGET})")

SHELL_KEYWORDS = {"if", "then", "elif", "else", "for", "while", "until", "do", "!", "{"}
WRAPPERS = {"sudo", "command", "env", "time", "nohup", "nice", "exec", "xargs", "timeout"}
SHELLS = {"sh", "bash", "zsh", "dash"}
GUARDED = {"git", "gh", "terraform", "tofu", "docker", "rm", "aws", "eval"} | SHELLS
TERRAFORM_DENIED = {"apply", "destroy", "import", "taint", "untaint", "force-unlock"}
TERRAFORM_STATE_DENIED = {"rm", "mv", "push", "pull", "replace-provider"}
GIT_OPTIONS_WITH_VALUE = {"-c", "-C", "--git-dir", "--work-tree", "--namespace", "--exec-path"}
GH_READ_ONLY_PR = {"list", "view", "diff", "status", "checks"}


def split_segments(command: str) -> list[list[str]]:
    """Split into simple commands on shell operators, including those inside $() and backticks."""
    lexer = shlex.shlex(command.replace("\n", " ; "), posix=True, punctuation_chars=";|&()`")
    lexer.whitespace_split = True
    lexer.commenters = ""
    segments: list[list[str]] = [[]]
    for token in lexer:
        if token and all(c in ";|&()`" for c in token):
            segments.append([])
        else:
            segments[-1].append(token)
    return [segment for segment in segments if segment]


def base(word: str) -> str:
    return word.rsplit("/", 1)[-1]


def strip_leading(argv: list[str]) -> list[str]:
    """Drop shell keywords and env assignments so `if x; then A=1 git push` is seen as `git push`."""
    index = 0
    while index < len(argv) and (
        argv[index] in SHELL_KEYWORDS or re.fullmatch(r"[A-Za-z_]\w*=.*", argv[index])
    ):
        index += 1
    return argv[index:]


def git_subcommand(args: list[str]) -> tuple[str, list[str]]:
    index = 0
    while index < len(args) and args[index].startswith("-"):
        index += 2 if args[index] in GIT_OPTIONS_WITH_VALUE else 1
    return (args[index], args[index + 1 :]) if index < len(args) else ("", [])


def check_git(args: list[str]) -> str | None:
    if "-c" in args and any("core." in value or "alias." in value for value in args):
        return "git -c overriding core or alias settings"
    subcommand, rest = git_subcommand(args)
    if subcommand == "push" or (subcommand == "subtree" and "push" in rest):
        return "git push"
    if subcommand == "commit" and (
        "--no-verify" in rest or any(re.fullmatch(r"-[a-zA-Z]*n[a-zA-Z]*", a) for a in rest)
    ):
        return "git commit --no-verify"
    if subcommand == "reset" and "--hard" in rest:
        return "git reset --hard"
    if subcommand == "clean" and (
        "--force" in rest or any(re.fullmatch(r"-[a-zA-Z]*f[a-zA-Z]*", a) for a in rest)
    ):
        return "git clean -f"
    if subcommand == "restore" and not {"--staged", "-S"} & set(rest):
        return "git restore discards working changes"
    if subcommand == "checkout" and "--" in rest:
        return "git checkout -- discards working changes"
    if subcommand == "config" and ("--global" in rest or "core.hooksPath" in rest):
        return "git config changing global settings or hooks"
    if subcommand == "remote" and rest[:1] in (["add"], ["set-url"]):
        return "changing git remotes"
    return None


def check_gh(args: list[str]) -> str | None:
    if not args:
        return None
    group, action = args[0], args[1] if len(args) > 1 else ""
    if group in {"search", "help"}:
        return None
    if group == "auth" and action == "status" and not {"--show-token", "-t"} & set(args):
        return None
    if group == "extension" and action == "list":
        return None
    if group == "pr" and action in GH_READ_ONLY_PR:
        return None
    if group == "run" and action in {"list", "view", "watch"}:
        return None
    if group == "api":
        joined = " ".join(args)
        if re.search(r"(-X|--method)[ =]?(POST|PUT|PATCH|DELETE)", joined, re.IGNORECASE):
            return "gh api write"
        if re.search(r"(^|\s)(-f|-F|--field|--raw-field|--input)\b", joined):
            return "gh api write"
        return None
    return f"gh {group} {action} (only read commands are allowed)"


def check_terraform(args: list[str]) -> str | None:
    positional = [a for a in args if not a.startswith("-")]
    if not positional:
        return None
    if positional[0] in TERRAFORM_DENIED:
        return f"terraform {positional[0]}"
    if positional[0] == "state" and positional[1:2] and positional[1] in TERRAFORM_STATE_DENIED:
        return f"terraform state {positional[1]}"
    return None


def check_docker(args: list[str]) -> str | None:
    positional = [a for a in args if not a.startswith("-")]
    if "--push" in args:
        return "docker --push"
    if positional[:1] in (["push"], ["login"], ["logout"]):
        return f"docker {positional[0]}"
    if {"image", "push"} <= set(positional) or {"compose", "push"} <= set(positional):
        return "docker push"
    return None


def check_rm(args: list[str]) -> str | None:
    short_flags = "".join(a[1:] for a in args if re.fullmatch(r"-[a-zA-Z]+", a))
    if "r" not in short_flags.lower() and "--recursive" not in args:
        return None
    for target in (a for a in args if not a.startswith("-")):
        cleaned = target.rstrip("/") or "/"
        parts = cleaned.split("/")
        if cleaned.startswith("/tmp/") and ".." not in parts:
            continue
        if (
            cleaned.startswith(("/", "~", "$"))
            or ".." in parts
            or parts[0] in {".git", ".claude", "*"}
            or cleaned in {".", "./*"}
        ):
            return f"recursive rm of {target}"
    return None


def check_segment(argv: list[str], depth: int) -> str | None:
    argv = strip_leading(argv)
    if not argv:
        return None
    program, args = base(argv[0]), argv[1:]
    if program in WRAPPERS or (program == "uv" and args[:1] == ["run"]):
        for index, word in enumerate(args):
            if base(word) in GUARDED:
                return check_segment(args[index:], depth)
        return None
    if program == "eval":
        return check_command(" ".join(args), depth + 1)
    if program in SHELLS:
        for index, arg in enumerate(args):
            if re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", arg) and index + 1 < len(args):
                return check_command(args[index + 1], depth + 1)
        return None
    if program == "git":
        return check_git(args)
    if program == "gh":
        return check_gh(args)
    if program in {"terraform", "tofu"}:
        return check_terraform(args)
    if program == "docker":
        return check_docker(args)
    if program == "rm":
        return check_rm(args)
    if program == "aws" and args[:1] not in (["--version"], ["help"]):
        return "aws (cloud access needs owner approval)"
    return None


def check_command(command: str, depth: int = 0) -> str | None:
    if depth > 4:
        return "command nesting too deep to check"
    if BYPASS.search(command):
        return "permission or sandbox bypass flag"
    if PIPE_TO_SHELL.search(command) or SUBSTITUTION_TO_SHELL.search(command):
        return "running a download in a shell"
    if SECRET_PATH.search(command):
        return "credential path"
    if SECRET_ENV_FILE.search(command):
        return ".env file"
    if SHELL_WRITE.search(command) or SED_IN_PLACE.search(command):
        return "writing a protected file through the shell"
    try:
        segments = split_segments(command)
    except ValueError:
        return "command could not be parsed"
    for segment in segments:
        reason = check_segment(segment, depth)
        if reason:
            return reason
    for match in SUBSTITUTION.finditer(command):  # Quoted substitutions are one lexer token.
        reason = check_command(match[1] or match[2] or "", depth + 1)
        if reason:
            return reason
    return None


def main() -> None:
    try:
        command = json.load(sys.stdin).get("tool_input", {}).get("command", "")
        reason = check_command(command)
    except Exception as error:  # noqa: BLE001 - a broken guard must block, never allow.
        reason = f"guard error ({type(error).__name__})"
    if reason:
        print(
            f"Blocked by .claude/hooks/guard_bash.py: {reason}. Do not work around this. "
            "If it is needed, ask the owner, who can run it with `! <command>`.",
            file=sys.stderr,
        )
        sys.exit(2)


if __name__ == "__main__":
    main()
