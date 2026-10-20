"""Common vocabulary for detectors.

A detector produces Candidates. A Candidate is a location plus whatever the
detector knew about it, and nothing more: deciding whether it is a true positive
is the evaluator's job, and keeping those apart is what makes it possible to run
the same evaluation over a static pass, an LLM pass and a fused pass.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Candidate:
    detector: str
    rule_id: str
    file: str
    line: int
    message: str = ""
    sink: str = ""
    confidence: str = ""
    extra: dict = field(default_factory=dict)

    def key(self) -> tuple[str, int, str]:
        return (self.file, self.line, self.detector)

    def as_dict(self) -> dict:
        return {"detector": self.detector, "rule_id": self.rule_id, "file": self.file,
                "line": self.line, "message": self.message, "sink": self.sink,
                "confidence": self.confidence, "extra": self.extra}


@dataclass
class DetectorRun:
    """One detector configuration applied to one target set.

    ``control_by_file`` is not decoration. A run whose positive control came
    back empty is reported as a failed run, because a zero from a detector that
    does not work looks exactly like a zero from a clean codebase. The counts
    are kept per control file and every one of them has to be non-zero: a
    detector tier that covers two languages can have its Python half working
    and its JavaScript half silently loading nothing, and a single total would
    hide exactly that.
    """
    detector: str
    config: str
    candidates: list[Candidate] = field(default_factory=list)
    control_by_file: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    duration_s: float = 0.0
    scanned_files: int = 0

    @property
    def control_findings(self) -> int:
        return sum(self.control_by_file.values())

    @property
    def silent_controls(self) -> list[str]:
        return sorted(name for name, count in self.control_by_file.items() if count == 0)

    @property
    def usable(self) -> bool:
        return (bool(self.control_by_file) and not self.silent_controls
                and not self.errors)

    def status(self) -> str:
        if not self.control_by_file:
            return "UNUSABLE: no positive control was scanned"
        if self.silent_controls:
            return ("UNUSABLE: positive control produced no finding: "
                    + ", ".join(self.silent_controls))
        if self.errors:
            return f"UNUSABLE: {len(self.errors)} detector error(s)"
        return "ok"

    def as_dict(self) -> dict:
        return {"detector": self.detector, "config": self.config,
                "candidates": [c.as_dict() for c in self.candidates],
                "control_by_file": self.control_by_file,
                "control_findings": self.control_findings,
                "errors": self.errors, "duration_s": round(self.duration_s, 2),
                "scanned_files": self.scanned_files, "status": self.status()}
