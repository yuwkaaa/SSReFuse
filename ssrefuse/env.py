"""Load `.env` into the environment, without a dependency and without surprises.

The key has to reach `ssrefuse.llm.client`, which reads `os.environ`. Shipping
a loader rather than telling people to `export` is worth the twenty lines: a
key exported in one terminal and missing in the next produces a run that falls
back to nothing, and the cheapest way for that to go wrong is for someone to
believe a judge ran when it did not.

Three rules, because a loader that is clever about secrets is a loader nobody
should trust:

* a variable already in the environment wins. An explicit `export` is a
  deliberate act and a file on disk must not silently override it.
* values are never printed, logged or written to results. The loader reports
  which *names* it set and nothing else.
* a `.env` readable by anyone but its owner is reported. It is not an error --
  that is the operator's call -- but it is not passed over in silence either.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from ssrefuse.corpus import REPO_ROOT

ENV_FILE = REPO_ROOT / ".env"


def parse(text: str) -> dict[str, str]:
    """Parse the KEY=VALUE subset that a `.env` actually needs.

    Handles `export KEY=value`, surrounding single or double quotes, blank
    lines and `#` comments. It deliberately does not do variable expansion or
    multi-line values: a loader that interprets its input is a loader that can
    surprise you about what your key is.
    """
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        name, _, value = line.partition("=")
        name = name.strip()
        if not name:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[name] = value
    return out


def load(path: Path | str = ENV_FILE) -> dict[str, str]:
    """Set anything in the file that is not already set. Returns a report.

    The report maps a variable name to what happened to it -- `set`, `kept`
    (already in the environment) or `empty` -- so a caller can say which keys
    are live without ever handling a value.
    """
    path = Path(path)
    report: dict[str, str] = {}
    if not path.exists():
        return report

    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        report["_permissions"] = f"{path.name} is mode {mode:o}, readable beyond its owner"

    for name, value in parse(path.read_text()).items():
        if not value:
            report[name] = "empty"
        elif os.environ.get(name):
            report[name] = "kept"
        else:
            os.environ[name] = value
            report[name] = "set"
    return report


def describe(report: dict[str, str]) -> str:
    """A line safe to print: names and outcomes, never values."""
    note = report.get("_permissions", "")
    names = [f"{k}={v}" for k, v in sorted(report.items()) if not k.startswith("_")]
    if not names:
        return note
    return ", ".join(names) + (f"  [{note}]" if note else "")
