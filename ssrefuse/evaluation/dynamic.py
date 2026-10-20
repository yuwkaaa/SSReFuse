"""Turn probe outcomes into the bypass matrix and the checks that police it.

Three things come out of here, and they are deliberately separate:

1. The matrix: one row per lab variant, one column per attack family, filled
   from measurements rather than from anyone's expectation.
2. Label confirmation. A variant labelled vulnerable whose every payload was
   blocked is not evidence of a strong guard, it is an unproven label, and it is
   reported as such instead of being quietly averaged into the totals.
3. Declared against measured. A bypass the catalog declared and the harness
   could not reproduce is a defect in the lab or the catalog; extra bypasses the
   harness found are informational, because declaring is about catching
   regressions and not about enumerating everything that happens to work.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ssrefuse.corpus import Corpus
from ssrefuse.harness import payloads as catalog

# Strongest-evidence-wins order when several concrete values share a family.
VERDICT_RANK = {
    "reached_internal": 5,
    "oob_confirmed": 4,
    "reached_benign": 3,
    "no_internal_contact": 2,
    "sink_error": 2,
    "blocked": 1,
    "not_applicable": 0,
}

CELL_SYMBOL = {
    "reached_internal": "X",
    "oob_confirmed": "o",
    "reached_benign": "=",
    "no_internal_contact": ".",
    "sink_error": "e",
    "blocked": "-",
    "not_applicable": " ",
}

CELL_LEGEND = [
    ("X", "reached an internal target: bypass confirmed"),
    ("-", "the application refused the input"),
    ("e", "the fetch was attempted and failed in the client"),
    (".", "the fetch happened but no internal target was reached"),
    ("o", "out-of-band canary fired (instrument, not a bypass)"),
    ("=", "control payload reached the allowlisted partner host"),
    (" ", "no value for this injection shape"),
]

BYPASS_VERDICTS = {"reached_internal"}


@dataclass
class Cell:
    variant: str
    family: str
    verdict: str
    evidence: str
    payload: str
    values_tried: int = 0
    values_reached: int = 0

    @property
    def symbol(self) -> str:
        return CELL_SYMBOL.get(self.verdict, "?")

    @property
    def is_bypass(self) -> bool:
        return self.verdict in BYPASS_VERDICTS


@dataclass
class DynamicEvaluation:
    cells: dict[tuple[str, str], Cell]
    variants: list[str]
    families: list[str]
    totals: dict[str, int] = field(default_factory=dict)
    unproven_vulnerable: list[str] = field(default_factory=list)
    safe_with_bypass: list[str] = field(default_factory=list)
    declared_not_measured: dict[str, list[str]] = field(default_factory=dict)
    measured_not_declared: dict[str, list[str]] = field(default_factory=dict)
    control_failures: list[str] = field(default_factory=list)
    control_passes: int = 0
    control_not_applicable: list[str] = field(default_factory=list)
    blind_confirmed: list[str] = field(default_factory=list)

    @property
    def problems(self) -> list[str]:
        out = []
        if self.unproven_vulnerable:
            out.append("variants labelled vulnerable with no reproduced bypass: "
                       + ", ".join(self.unproven_vulnerable))
        if self.safe_with_bypass:
            out.append("variants labelled safe that a payload got through: "
                       + ", ".join(self.safe_with_bypass))
        if self.declared_not_measured:
            out.append("declared bypasses that did not reproduce: " + ", ".join(
                f"{k}({', '.join(v)})" for k, v in sorted(self.declared_not_measured.items())))
        if self.control_failures:
            out.append("control payload did not reach the partner host on: "
                       + ", ".join(self.control_failures))
        return out

    def bypass_count(self, variant: str) -> int:
        return sum(1 for (vid, fam), cell in self.cells.items()
                   if vid == variant and cell.is_bypass and fam in self.families)

    def family_count(self, family: str) -> int:
        return sum(1 for (vid, fam), cell in self.cells.items()
                   if fam == family and cell.is_bypass)


def evaluate(corpus: Corpus, probe_result: dict) -> DynamicEvaluation:
    rows = [o for run in probe_result.get("runs", []) for o in run.get("outcomes", [])]

    cells: dict[tuple[str, str], Cell] = {}
    for row in rows:
        key = (row["variant"], row["family"])
        current = cells.get(key)
        incoming = Cell(row["variant"], row["family"], row["verdict"], row["evidence"],
                        row["payload"])
        if current is None:
            cells[key] = incoming
            current = incoming
        elif VERDICT_RANK[row["verdict"]] > VERDICT_RANK[current.verdict]:
            incoming.values_tried = current.values_tried
            incoming.values_reached = current.values_reached
            cells[key] = incoming
            current = incoming
        if row["verdict"] != "not_applicable":
            current.values_tried += 1
        if row["verdict"] in BYPASS_VERDICTS:
            current.values_reached += 1

    variant_ids = [v.id for v in corpus.variants]
    families = sorted(catalog.ATTACK_FAMILIES)

    result = DynamicEvaluation(cells=cells, variants=variant_ids, families=families)

    verdict_totals: dict[str, int] = {}
    for row in rows:
        verdict_totals[row["verdict"]] = verdict_totals.get(row["verdict"], 0) + 1
    verdict_totals["probe_rows"] = len(rows)
    result.totals = verdict_totals

    for variant in corpus.variants:
        measured = {fam for (vid, fam), cell in cells.items()
                    if vid == variant.id and cell.is_bypass}
        attack_measured = measured & set(families)

        if variant.label == "vulnerable" and not attack_measured:
            result.unproven_vulnerable.append(variant.id)
        if variant.label == "safe" and attack_measured:
            result.safe_with_bypass.append(variant.id)

        declared = set(variant.bypasses_declared)
        missing = sorted(declared - measured)
        extra = sorted(attack_measured - declared)
        if missing:
            result.declared_not_measured[variant.id] = missing
        if extra:
            result.measured_not_declared[variant.id] = extra

        control = cells.get((variant.id, catalog.CONTROL_FAMILY))
        if control is None or control.verdict == "not_applicable" or variant.no_sink:
            # Either the injection shape has no control value, or the route sends
            # no request at all, so there is nothing for a control to reach. Kept
            # in its own list: a control that cannot run is not a control that
            # passed, and it is not a control that failed either.
            result.control_not_applicable.append(variant.id)
        elif control.verdict == "reached_benign":
            result.control_passes += 1
        else:
            result.control_failures.append(f"{variant.id}({control.verdict})")

        if variant.observability == "blind":
            for family in catalog.INSTRUMENT_FAMILIES:
                cell = cells.get((variant.id, family))
                if cell and cell.verdict == "oob_confirmed":
                    result.blind_confirmed.append(variant.id)
                    break

    return result
