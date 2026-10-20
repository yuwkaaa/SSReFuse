"""Detector metrics against the labelled corpus.

Two label sets are scored side by side. The declared label is what the corpus
says; the confirmed label is what the prober reproduced. On this lab they agree,
and the machinery still matters: on real applications they will not, and a
precision figure computed against labels nobody reproduced is a claim about a
spreadsheet rather than about software.

Candidates that fall outside every labelled region are counted and listed
instead of being dropped. An unattributed finding is neither a true nor a false
positive until a person looks at it, and a pipeline that silently discards them
reports a precision it did not earn.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ssrefuse.corpus import Corpus, Variant
from ssrefuse.detectors.base import Candidate, DetectorRun
from ssrefuse.evaluation.dynamic import DynamicEvaluation


@dataclass
class Scores:
    label_source: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p and r else None

    def fmt(self, value: float | None) -> str:
        return "n/a" if value is None else f"{value:.3f}"

    def line(self) -> str:
        return (f"TP={self.tp} FP={self.fp} FN={self.fn} TN={self.tn} "
                f"P={self.fmt(self.precision)} R={self.fmt(self.recall)} "
                f"F1={self.fmt(self.f1)}")


@dataclass
class DetectorEvaluation:
    detector: str
    status: str
    usable: bool
    candidates: int
    attributed: int
    unattributed: list[Candidate] = field(default_factory=list)
    via_shared: int = 0
    flagged: set[str] = field(default_factory=set)
    per_variant_counts: dict[str, int] = field(default_factory=dict)
    against_declared: Scores = field(default_factory=lambda: Scores("declared"))
    against_confirmed: Scores = field(default_factory=lambda: Scores("confirmed"))
    false_positives: list[str] = field(default_factory=list)
    false_negatives: list[str] = field(default_factory=list)


def _confirmed_vulnerable(corpus: Corpus, dyn: DynamicEvaluation | None) -> set[str]:
    if dyn is None:
        return {v.id for v in corpus.variants if v.label == "vulnerable"}
    return {v.id for v in corpus.variants if dyn.bypass_count(v.id) > 0}


def score_run(corpus: Corpus, run: DetectorRun,
              dyn: DynamicEvaluation | None = None) -> DetectorEvaluation:
    ev = DetectorEvaluation(detector=run.detector, status=run.status(),
                            usable=run.usable, candidates=len(run.candidates),
                            attributed=0)
    for candidate in run.candidates:
        owners = corpus.attribute_all(candidate.file, candidate.line)
        if not owners:
            ev.unattributed.append(candidate)
            continue
        ev.attributed += 1
        if len(owners) > 1 or not owners[0].covers_directly(candidate.file, candidate.line):
            ev.via_shared += 1
        for variant in owners:
            ev.flagged.add(variant.id)
            ev.per_variant_counts[variant.id] = ev.per_variant_counts.get(variant.id, 0) + 1

    confirmed = _confirmed_vulnerable(corpus, dyn)
    for variant in corpus.variants:
        hit = variant.id in ev.flagged
        for scores, is_vuln in ((ev.against_declared, variant.label == "vulnerable"),
                                (ev.against_confirmed, variant.id in confirmed)):
            if hit and is_vuln:
                scores.tp += 1
            elif hit and not is_vuln:
                scores.fp += 1
            elif not hit and is_vuln:
                scores.fn += 1
            else:
                scores.tn += 1
        if hit and variant.label == "safe":
            ev.false_positives.append(variant.id)
        if not hit and variant.label == "vulnerable":
            ev.false_negatives.append(variant.id)
    return ev


def evaluate_runs(corpus: Corpus, runs: list[DetectorRun],
                  dyn: DynamicEvaluation | None = None) -> list[DetectorEvaluation]:
    return [score_run(corpus, run, dyn) for run in runs]
