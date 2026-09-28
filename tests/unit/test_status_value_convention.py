"""Regression: no bare AgentStatus Enum is assigned to `status` anywhere in src/.

review criterion #15: every `status` field assignment MUST use `AgentStatus.<X>.value` (the string),
not the bare `AgentStatus.<X>` Enum member. Because `AgentStatus` subclasses `str`, equality
assertions (`== AgentStatus.SUCCESS`) pass for both forms and cannot catch a bare-Enum regression.
This source-level guard fails if any `AgentStatus.<NAME>` occurrence in src/ is not immediately
followed by `.value` — the project-wide convention for status assignments and comparisons.
"""

import pathlib
import re

_SRC = pathlib.Path(__file__).resolve().parents[2] / "src"
# AgentStatus.<UPPER> NOT already followed by .value
_BARE = re.compile(r"AgentStatus\.[A-Z_]+\b(?!\.value)")


def test_no_bare_agentstatus_in_src():
    offenders = []
    for py in _SRC.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        for i, line in enumerate(text.splitlines(), 1):
            # skip the import line and any 'from ... import AgentStatus'
            if "import" in line and "AgentStatus" in line:
                continue
            if _BARE.search(line):
                offenders.append(f"{py.relative_to(_SRC.parent)}:{i}: {line.strip()}")
    assert not offenders, "bare AgentStatus (missing .value) found:\n" + "\n".join(offenders)
