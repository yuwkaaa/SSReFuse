"""Fusion strategies, scored side by side.

Each strategy is a different answer to the same question: given a candidate set
and a judgement about each candidate, which variants do we report? Running them
all over one set of measurements is what makes the comparison honest -- the
numbers differ only by the decision rule, not by the run.

  static_only     every variant a static detector flagged
  llm_only        every variant the judge called vulnerable, over the
                  recall-oriented candidate set
  fuse_and        flagged by taint analysis and called vulnerable by the judge
  fuse_cascade    static analysis proposes, the judge disposes, and anything the
                  judge refuses to decide is settled by the prober

The cascade is the pipeline this project argues for, and the row that matters is
how many variants it resolved through the prober rather than by assertion.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ssrefuse.corpus import Corpus
from ssrefuse.detectors.base import DetectorRun
from ssrefuse.detectors.llm_judge import Judgement
from ssrefuse.evaluation.dynamic import DynamicEvaluation
from ssrefuse.evaluation.static import Scores


@dataclass
class StrategyResult:
    name: str
    description: str
    flagged: set[str] = field(default_factory=set)
    scores: Scores = field(default_factory=lambda: Scores("declared"))
    resolved_by_prober: list[str] = field(default_factory=list)
    undecided: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # Scores restricted to the variants the judge decided by itself. Where the
    # prober settled a cell, the cascade's answer and the label come from the
    # same measurement, so scoring that cell against that label says nothing.
    scores_judge_decided: Scores | None = None
    judge_decided: list[str] = field(default_factory=list)


def _flagged_by(corpus: Corpus, run: DetectorRun) -> set[str]:
    flagged: set[str] = set()
    for candidate in run.candidates:
        for variant in corpus.attribute_all(candidate.file, candidate.line):
            flagged.add(variant.id)
    return flagged


def _judgement_map(corpus: Corpus, judgements: list[Judgement]) -> dict[str, Judgement]:
    """Best judgement per variant: a vulnerable verdict wins, then confidence."""
    best: dict[str, Judgement] = {}
    for judgement in judgements:
        for variant in corpus.attribute_all(judgement.file, judgement.line):
            current = best.get(variant.id)
            if current is None:
                best[variant.id] = judgement
                continue
            rank = {"vulnerable": 2, "needs_dynamic_test": 1, "safe": 0}
            if (rank[judgement.verdict], judgement.confidence) > \
               (rank[current.verdict], current.confidence):
                best[variant.id] = judgement
    return best


def _score(corpus: Corpus, flagged: set[str], only: set[str] | None = None) -> Scores:
    scores = Scores("declared")
    for variant in corpus.variants:
        if only is not None and variant.id not in only:
            continue
        hit = variant.id in flagged
        vulnerable = variant.label == "vulnerable"
        if hit and vulnerable:
            scores.tp += 1
        elif hit:
            scores.fp += 1
        elif vulnerable:
            scores.fn += 1
        else:
            scores.tn += 1
    return scores


def run_strategies(corpus: Corpus, runs: dict[str, DetectorRun],
                   judgements: list[Judgement],
                   dyn: DynamicEvaluation | None = None) -> list[StrategyResult]:
    inventory = runs.get("inventory")
    taint = runs.get("taint-nosan") or runs.get("taint-naive")
    judged = _judgement_map(corpus, judgements)

    results: list[StrategyResult] = []

    if taint is not None:
        flagged = _flagged_by(corpus, taint)
        results.append(StrategyResult(
            "static_only", f"variants flagged by {taint.detector}", flagged,
            _score(corpus, flagged)))

    llm_flagged = {vid for vid, j in judged.items() if j.verdict == "vulnerable"}
    llm_result = StrategyResult(
        "llm_only", "variants the judge called vulnerable, over the inventory "
        "candidate set", llm_flagged, _score(corpus, llm_flagged))
    llm_result.undecided = sorted(vid for vid, j in judged.items()
                                  if j.verdict == "needs_dynamic_test")
    results.append(llm_result)

    if taint is not None:
        both = _flagged_by(corpus, taint) & llm_flagged
        results.append(StrategyResult(
            "fuse_and", "flagged by taint analysis and called vulnerable by the "
            "judge", both, _score(corpus, both)))

    if inventory is not None:
        proposed = _flagged_by(corpus, inventory)
        flagged = set()
        cascade = StrategyResult(
            "fuse_cascade",
            "static analysis proposes, the judge disposes, the prober settles "
            "what the judge declines to decide")
        for vid in sorted(proposed):
            judgement = judged.get(vid)
            if judgement is None:
                cascade.notes.append(f"{vid}: proposed but never judged")
                cascade.undecided.append(vid)
                continue
            if judgement.verdict == "vulnerable":
                flagged.add(vid)
            elif judgement.verdict == "safe":
                continue
            elif dyn is not None:
                cascade.resolved_by_prober.append(vid)
                if dyn.bypass_count(vid) > 0:
                    flagged.add(vid)
            else:
                cascade.undecided.append(vid)
        cascade.flagged = flagged
        cascade.scores = _score(corpus, flagged)
        decided = sorted(set(proposed) - set(cascade.resolved_by_prober)
                         - set(cascade.undecided))
        cascade.judge_decided = decided
        cascade.scores_judge_decided = _score(corpus, flagged, only=set(decided))
        if cascade.resolved_by_prober:
            cascade.notes.append(
                f"{len(cascade.resolved_by_prober)} of {len(proposed)} proposed "
                f"variants were settled by the prober rather than by the judge. "
                f"On those, the cascade's verdict and the label it is scored "
                f"against come from the same measurement, so the overall row is "
                f"circular to that extent. The judge-decided row beside it is the "
                f"one that says something about the model.")
        results.append(cascade)

    return results
