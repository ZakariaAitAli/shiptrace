#!/usr/bin/env python3
"""PreToolUse hook for reviewer agents: Bash is limited to a read-only allowlist.

Allowlist, not denylist: anything unrecognized is refused.
"""

import json
import re
import shlex
import sys

READ_ONLY = {"cat", "cut", "find", "grep", "head", "ls", "rg", "sort", "tail", "tr", "wc"}
GIT_READ_ONLY = {"blame", "diff", "log", "ls-files", "merge-base", "rev-parse", "show", "status"}
FIND_FORBIDDEN = {
    "-delete",
    "-exec",
    "-execdir",
    "-ok",
    "-okdir",
    "-fprint",
    "-fprint0",
    "-fprintf",
    "-fls",
}
GIT_FORBIDDEN = re.compile(r"^(--output|--ext-diff|--textconv|-O)")
SECRETS = re.compile(
    r"\.env(\.(?!example\b)|$)|\.ssh|\.aws|\.config/gh|\.credentials|\.pem$|\.key$"
    r"|\.pgpass|\.netrc|\.tfstate"
)
FORBIDDEN_SYNTAX = re.compile(r"[><`\n]|\$\(|\$\{|(?<!&)&(?!&)|\|&")


def split_pipeline(command: str) -> list[list[str]]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";|&")
    lexer.whitespace_split = True
    lexer.commenters = ""
    segments: list[list[str]] = [[]]
    for token in lexer:
        if token in {"|", "&&", "||", ";"}:
            segments.append([])
        else:
            segments[-1].append(token)
    return segments


def check_segment(argv: list[str]) -> str | None:
    if not argv:
        return "empty command segment"
    program, args = argv[0], argv[1:]
    if any(SECRETS.search(arg) for arg in args):
        return "secret path"
    if program == "git":
        if not args or args[0] not in GIT_READ_ONLY:
            return f"git {args[0] if args else ''} is not on the read-only list"
        if any(GIT_FORBIDDEN.match(arg) for arg in args):
            return "forbidden git option"
        return None
    if program == "find" and FIND_FORBIDDEN.intersection(args):
        return "forbidden find action"
    if program == "sort" and any(arg.startswith(("-o", "--o", "--c")) for arg in args):
        return "sort option that writes files or runs programs"
    if program == "rg" and any(arg.startswith("--pre") for arg in args):
        return "rg preprocessor"
    if program not in READ_ONLY:
        return f"{program} is not on the read-only list"
    return None


def check_command(command: str) -> str | None:
    if FORBIDDEN_SYNTAX.search(command):
        return "redirection, substitution or background syntax"
    try:
        segments = split_pipeline(command)
    except ValueError:
        return "command could not be parsed"
    for segment in segments:
        problem = check_segment(segment)
        if problem:
            return problem
    return None


def main() -> None:
    try:
        problem = check_command(json.load(sys.stdin).get("tool_input", {}).get("command", ""))
    except Exception as error:  # noqa: BLE001 - a broken guard must block, never allow.
        problem = f"guard error ({type(error).__name__})"
    if problem:
        print(
            f"Reviewer Bash is read-only: {problem}. Report findings; do not change anything.",
            file=sys.stderr,
        )
        sys.exit(2)


if __name__ == "__main__":
    main()
