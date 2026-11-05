# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 Jason Ricca and CambiOS contributors
"""
Which commits an AI agent wrote, as far as a commit message can say.

A commit is agent-authored when it carries a `Co-Authored-By:` trailer
that names an agent. The hooks that apply to agent-authored commits
import this pattern, so the list of agent names lives in one place.

The pattern can only see a trailer that is there. CONTRIBUTING.md asks
for the trailer; nothing can require it of a commit that omits it.
"""

import re

# Deferred: a name not on this list is not recognised.
# Why: there is no registry of agent names to derive the list from.
# Revisit when: a commit lands whose Co-Authored-By trailer names an
# agent this pattern does not match.
AGENT_NAMES = ("Claude", "Codex", "ChatGPT", "GPT", "Copilot", "Gemini", "Cursor", "Devin", "cambios-agent")

AGENT_TRAILER_RE = re.compile(
    r"^Co-Authored-By:\s*(?:" + "|".join(re.escape(n) for n in AGENT_NAMES) + r")\b",
    re.IGNORECASE | re.MULTILINE,
)


def is_agent_authored(message):
    return bool(AGENT_TRAILER_RE.search(message))
