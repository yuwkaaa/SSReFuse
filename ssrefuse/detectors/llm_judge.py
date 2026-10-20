"""The LLM judge: slice, ask, and let the model ask back.

One round is a single-shot prompt, which is what the published LLM-assisted SSRF
detectors do. This judge runs up to ``max_rounds``: when the model answers
``needs_dynamic_test`` and names functions or constants it wants to see, the
slicer widens the slice and the question is asked again. That loop is the whole
difference between a model guessing from a window and a model reading the code,
and because the extra rounds are recorded per candidate, the cost of the loop
and the answers it changed can both be reported.

A judgement is a hypothesis. It is scored against the corpus, and where it says
``needs_dynamic_test`` the prober is what settles it.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from ssrefuse.corpus import REPO_ROOT, Corpus
from ssrefuse.detectors.base import Candidate
from ssrefuse.llm.client import LLMClient
from ssrefuse.llm.prompts import SYSTEM, build_prompt
from ssrefuse.slicing import slice_source

VERDICTS = ("vulnerable", "safe", "needs_dynamic_test")


@dataclass
class Judgement:
    file: str
    line: int
    detector: str
    lang: str = ""
    verdict: str = "needs_dynamic_test"
    confidence: float = 0.0
    bypass_families: list[str] = field(default_factory=list)
    reasoning: str = ""
    unknowns: list[str] = field(default_factory=list)
    same_value_validated_and_fetched: bool | None = None
    guard_survives: dict = field(default_factory=dict)
    rounds: int = 0
    requested: dict = field(default_factory=dict)
    slice_lines: int = 0
    provider: str = ""
    model: str = ""
    is_mock: bool = False
    cached: bool = False
    reasoning_effort: str = ""
    reasoning_tokens: int = 0
    reasoning_chars: int = 0
    json_mode_refused: bool = False
    parse_error: str = ""
    raw: str = ""

    def as_dict(self) -> dict:
        data = dict(vars(self))
        data["raw"] = self.raw[:4000]
        return data


def _extract_json(text: str) -> tuple[dict, str]:
    try:
        return json.loads(text), ""
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0)), "answer contained prose around the JSON"
        except json.JSONDecodeError as exc:
            return {}, f"unparsable JSON: {exc}"
    return {}, "no JSON object in the answer"


class LLMJudge:
    def __init__(self, client: LLMClient, max_rounds: int = 2, slice_depth: int = 2,
                 strip_comments: bool = True):
        self.client = client
        self.max_rounds = max_rounds
        self.slice_depth = slice_depth
        self.strip_comments = strip_comments

    def judge_location(self, file: str, line: int, detector: str,
                       hint: dict | None = None) -> Judgement:
        hint = dict(hint or {})
        judgement = Judgement(file=file, line=line, detector=detector,
                              provider=self.client.provider, model=self.client.model,
                              is_mock=self.client.is_mock,
                              reasoning_effort=self.client.reasoning_effort)
        extra_functions: list[str] = []
        extra_values: list[str] = []
        previous: dict | None = None

        for round_number in range(1, self.max_rounds + 1):
            code_slice = slice_source(
                REPO_ROOT / file if not str(file).startswith("/") else file,
                line, depth=self.slice_depth, strip=self.strip_comments,
                include_functions=extra_functions, include_values=extra_values)
            hint["unresolved_calls"] = code_slice.unresolved_calls
            hint["slice_notes"] = code_slice.notes
            hint["detector"] = detector
            prompt = build_prompt(code_slice.render(), hint, round_number, previous)
            judgement.lang = str(hint.get("lang", ""))

            completion = self.client.complete(prompt, system=SYSTEM)
            answer, parse_note = _extract_json(completion.text)

            judgement.rounds = round_number
            judgement.slice_lines = code_slice.line_count()
            judgement.raw = completion.text
            judgement.cached = completion.cached
            judgement.reasoning_effort = self.client.reasoning_effort
            judgement.reasoning_tokens += completion.reasoning_tokens
            judgement.reasoning_chars += len(completion.reasoning)
            judgement.json_mode_refused = (judgement.json_mode_refused
                                           or completion.json_mode_refused)
            judgement.parse_error = parse_note
            if not answer:
                return judgement

            verdict = str(answer.get("verdict", "")).strip()
            judgement.verdict = verdict if verdict in VERDICTS else "needs_dynamic_test"
            if verdict not in VERDICTS:
                judgement.parse_error = (judgement.parse_error + "; " if judgement.parse_error
                                         else "") + f"unknown verdict {verdict!r}"
            try:
                judgement.confidence = float(answer.get("confidence", 0.0))
            except (TypeError, ValueError):
                judgement.confidence = 0.0
            families = answer.get("bypass_families") or []
            judgement.bypass_families = [str(f) for f in families if isinstance(f, (str, int))]
            judgement.reasoning = str(answer.get("reasoning", ""))[:1200]
            judgement.unknowns = [str(u) for u in (answer.get("unknowns") or [])][:10]
            judgement.same_value_validated_and_fetched = answer.get(
                "same_value_validated_and_fetched")
            judgement.guard_survives = answer.get("guard_survives") or {}
            request = answer.get("request_more") or {}
            judgement.requested = request

            wants_more = bool(request.get("functions") or request.get("module_values"))
            if judgement.verdict != "needs_dynamic_test" or not wants_more:
                return judgement
            extra_functions = [str(f) for f in (request.get("functions") or [])][:8]
            extra_values = [str(v) for v in (request.get("module_values") or [])][:8]
            previous = answer

        return judgement

    def judge_candidates(self, candidates: list[Candidate],
                         corpus: Corpus | None = None) -> list[Judgement]:
        """Judge each distinct location once, in corpus order for stable output."""
        seen: set[tuple[str, int]] = set()
        judgements: list[Judgement] = []
        for candidate in sorted(candidates, key=lambda c: (c.file, c.line)):
            key = (candidate.file, candidate.line)
            if key in seen:
                continue
            seen.add(key)
            hint: dict = {"lang": "python", "framework": "flask"}
            if corpus is not None:
                variant = corpus.attribute(candidate.file, candidate.line)
                if variant is not None:
                    hint["lang"] = variant.lang
                    hint["framework"] = corpus.apps[variant.app].framework
            judgements.append(self.judge_location(candidate.file, candidate.line,
                                                  candidate.detector, hint))
        return judgements
