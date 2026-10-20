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

    ``control_findings`` is not decoration. A run whose positive control came
    back empty is reported as a failed run, because a zero from a detector that
    does not work looks exactly like a zero from a clean codebase.
    """
    detector: str
    config: str
    candidates: list[Candidate] = field(default_factory=list)
    control_findings: int = 0
    control_file: str = ""
    errors: list[str] = field(default_factory=list)
    duration_s: float = 0.0
    scanned_files: int = 0

    @property
    def usable(self) -> bool:
        return self.control_findings > 0 and not self.errors

    def status(self) -> str:
        if self.control_findings == 0:
            return "UNUSABLE: positive control produced no finding"
        if self.errors:
            return f"UNUSABLE: {len(self.errors)} detector error(s)"
        return "ok"

    def as_dict(self) -> dict:
        return {"detector": self.detector, "config": self.config,
                "candidates": [c.as_dict() for c in self.candidates],
                "control_findings": self.control_findings, "control_file": self.control_file,
                "errors": self.errors, "duration_s": round(self.duration_s, 2),
                "scanned_files": self.scanned_files, "status": self.status()}
