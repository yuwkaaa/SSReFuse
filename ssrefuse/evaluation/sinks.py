"""Sink-inventory coverage over the static-only corpus.

The brief asks for the common sinks *per language*, naming `curl`,
`requests.get`, `file_get_contents` and `URLConnection`. Two of those live in
languages this project has no runnable lab for, and that is the whole reason
this module is separate from `evaluation/static.py`.

What is scored here is not precision and recall. Those need labels a prober
reproduced, and PHP and Java have none here: calling a file vulnerable because
it looks vulnerable is the thing this project refuses to do. What can be
measured without running anything is narrower and still worth having -- *of
the sinks that are in this file, how many does the rule see* -- so every sink
in the static-only corpus carries an `@ssrefuse:sink` marker and this module
reports found, missed and unmarked separately.

Three counts, never merged:

  found    a marked sink that a rule reported
  missed   a marked sink that no rule reported -- the number that matters,
           because it is the surface the detector is blind to
  unmarked a reported location with no marker near it. Not an error: it may
           be a real sink nobody marked, and it is listed so a person can say
           which, rather than being dropped into a precision figure it did
           not earn.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ssrefuse.corpus import REPO_ROOT

# Anchored at the start of a comment on its own line, which is what keeps a
# sentence of prose that happens to mention the marker from being read as one.
SINK_RE = re.compile(r"^\s*(?://|#|/\*)\s*@ssrefuse:sink\s+([\w.-]+)")

# A marked sink may be a few lines above the line a rule reports, because the
# call can be preceded by its own arguments or by a `try` line.
MATCH_WINDOW = 4

STATIC_ONLY = REPO_ROOT / "corpus" / "static_only"
LANGUAGE_BY_SUFFIX = {".php": "php", ".java": "java", ".js": "javascript",
                      ".py": "python", ".mjs": "javascript", ".cjs": "javascript"}


@dataclass
class SinkMarker:
    file: str
    line: int
    name: str


@dataclass
class FileCoverage:
    file: str
    language: str
    markers: list[SinkMarker] = field(default_factory=list)
    found: dict[str, int] = field(default_factory=dict)      # marker name -> line found
    missed: list[str] = field(default_factory=list)
    unmarked: list[int] = field(default_factory=list)

    @property
    def expected(self) -> int:
        return len(self.markers)


def scan_markers(root: Path | str = STATIC_ONLY) -> list[SinkMarker]:
    """Every marked sink in the static-only corpus."""
    root = Path(root)
    markers: list[SinkMarker] = []
    if not root.exists():
        return markers
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in LANGUAGE_BY_SUFFIX:
            continue
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            match = SINK_RE.match(line)
            if match:
                markers.append(SinkMarker(
                    str(path.relative_to(REPO_ROOT)), number, match.group(1)))
    return markers


def coverage(candidates, root: Path | str = STATIC_ONLY) -> list[FileCoverage]:
    """Compare what the rules reported against what is marked.

    ``candidates`` are detector Candidates from a scan of the static-only
    corpus. A candidate for a file with no markers at all is still reported,
    under `unmarked`, rather than silently discarded.
    """
    markers = scan_markers(root)
    by_file: dict[str, FileCoverage] = {}
    for marker in markers:
        suffix = Path(marker.file).suffix
        entry = by_file.setdefault(marker.file, FileCoverage(
            file=marker.file, language=LANGUAGE_BY_SUFFIX.get(suffix, suffix.lstrip("."))))
        entry.markers.append(marker)

    for candidate in candidates:
        name = Path(candidate.file).name
        key = next((f for f in by_file if Path(f).name == name), None)
        if key is None:
            suffix = Path(candidate.file).suffix
            key = candidate.file
            by_file.setdefault(key, FileCoverage(
                file=key, language=LANGUAGE_BY_SUFFIX.get(suffix, suffix.lstrip("."))))
        entry = by_file[key]
        hit = next((m for m in entry.markers
                    if m.line <= candidate.line <= m.line + MATCH_WINDOW
                    and m.name not in entry.found), None)
        if hit is not None:
            entry.found[hit.name] = candidate.line
        else:
            entry.unmarked.append(candidate.line)

    for entry in by_file.values():
        entry.missed = [m.name for m in entry.markers if m.name not in entry.found]
        entry.unmarked.sort()
    return [by_file[key] for key in sorted(by_file)]


def totals(entries: list[FileCoverage]) -> dict[str, int]:
    return {
        "files": len(entries),
        "expected": sum(e.expected for e in entries),
        "found": sum(len(e.found) for e in entries),
        "missed": sum(len(e.missed) for e in entries),
        "unmarked": sum(len(e.unmarked) for e in entries),
    }
