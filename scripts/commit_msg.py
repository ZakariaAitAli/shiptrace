#!/usr/bin/env python3
"""commit-msg hook: enforces ShipTrace's Conventional Commits rules. Usage: commit_msg.py <file>"""

import re
import sys
from pathlib import Path

TYPES = ("feat", "fix", "refactor", "test", "docs", "chore", "ci", "build", "perf", "security")
HEADER = re.compile(rf"^({'|'.join(TYPES)})(\([a-z0-9][a-z0-9-]*\))?!?: (?P<description>\S.*)$")
GENERIC = {"update", "updates", "fix", "fixes", "wip", "changes", "misc", "stuff", "tmp"}
PAST_TENSE = re.compile(r"^[a-z]+ed$")
AI_NAME = r"(claude|anthropic|chatgpt|openai|copilot|gemini|\bai\b)"
AI_ATTRIBUTION = (
    re.compile(rf"^co-authored-by:.*{AI_NAME}", re.IGNORECASE | re.MULTILINE),
    re.compile(rf"generated (with|by)\b.*{AI_NAME}", re.IGNORECASE),
    re.compile(r"\bai[- ]assisted\b", re.IGNORECASE),
    re.compile(r"noreply@anthropic\.com", re.IGNORECASE),
)
MAX_HEADER = 72


def problems(message: str) -> list[str]:
    lines = [line for line in message.splitlines() if not line.startswith("#")]
    text = "\n".join(lines).strip()
    if not text:
        return ["message is empty"]
    header = text.splitlines()[0]
    found = []
    match = HEADER.match(header)
    if not match:
        found.append(f"header must be <type>(<scope>): <description>; types: {', '.join(TYPES)}")
    else:
        description = match["description"]
        first_word = description.split()[0].lower()
        if description.lower().rstrip(".") in GENERIC:
            found.append("description is too generic")
        if PAST_TENSE.match(first_word) or first_word.endswith("ing"):
            found.append("description must be imperative, such as 'add', not 'added' or 'adding'")
        if description.endswith("."):
            found.append("description must not end with a period")
    if len(header) > MAX_HEADER:
        found.append(f"header is {len(header)} characters; limit is {MAX_HEADER}")
    if len(text.splitlines()) > 1 and text.splitlines()[1].strip():
        found.append("second line must be blank")
    if any(pattern.search(text) for pattern in AI_ATTRIBUTION):
        found.append("AI attribution is not allowed")
    return found


def main() -> int:
    found = problems(Path(sys.argv[1]).read_text(encoding="utf-8"))
    for problem in found:
        print(f"commit-msg: {problem}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
