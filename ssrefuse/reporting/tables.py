"""Markdown rendering of the evaluation tables.

The report prints the raw counts next to anything derived from them. A matrix
that shows only verdict symbols cannot be checked by a reader, so every table
carries the totals it was computed from.
"""
from __future__ import annotations

from ssrefuse.corpus import Corpus
from ssrefuse.evaluation.dynamic import CELL_LEGEND, DynamicEvaluation
from ssrefuse.harness import payloads as catalog


def bypass_matrix(corpus: Corpus, ev: DynamicEvaluation) -> str:
    families = ev.families
    short = {f: f.split("_")[0] for f in families}
    header = "| variant | label | guard | " + " | ".join(short[f] for f in families) + " | bypasses |"
    sep = "|" + "---|" * (len(families) + 4)
    lines = [header, sep]
    for variant in corpus.variants:
        guard = ", ".join(g.split("_")[0] for g in variant.guards) or "none"
        cells = []
        for family in families:
            cell = ev.cells.get((variant.id, family))
            cells.append(f"`{cell.symbol}`" if cell else "`?`")
        lines.append(f"| {variant.id} | {variant.label} | {guard} | "
                     + " | ".join(cells) + f" | {ev.bypass_count(variant.id)} |")
    lines.append("")
    lines.append("Legend: " + "; ".join(f"`{sym}` {text}" for sym, text in CELL_LEGEND))
    return "\n".join(lines)


def family_effectiveness(corpus: Corpus, ev: DynamicEvaluation) -> str:
    vulnerable = [v for v in corpus.variants if v.label == "vulnerable"]
    lines = ["| family | technique | variants bypassed | of vulnerable variants |",
             "|---|---|---|---|"]
    for family_id in ev.families:
        family = catalog.FAMILY_BY_ID[family_id]
        count = ev.family_count(family_id)
        lines.append(f"| {family_id} | {family.title} | {count} | {len(vulnerable)} |")
    return "\n".join(lines)


def guard_summary(corpus: Corpus, ev: DynamicEvaluation) -> str:
    """How each guard held up, grouped by the guard rather than by the route."""
    by_guard: dict[str, list] = {}
    for variant in corpus.variants:
        for guard in variant.guards or ["(none)"]:
            by_guard.setdefault(guard, []).append(variant)
    lines = ["| guard | variants | bypass families that worked |", "|---|---|---|"]
    for guard, variants in sorted(by_guard.items()):
        worked = sorted({fam for v in variants for (vid, fam), cell in ev.cells.items()
                         if vid == v.id and cell.is_bypass and fam in ev.families})
        shorts = ", ".join(f.split("_")[0] for f in worked) or "none reproduced"
        lines.append(f"| {guard} | {', '.join(v.id for v in variants)} | {shorts} |")
    return "\n".join(lines)


def integrity_section(ev: DynamicEvaluation) -> str:
    lines = ["### Run integrity", ""]
    lines.append(f"- probe rows: {ev.totals.get('probe_rows', 0)}")
    counts = ", ".join(f"{k}={v}" for k, v in sorted(ev.totals.items()) if k != "probe_rows")
    lines.append(f"- verdict totals: {counts}")
    lines.append(f"- control payload reached the partner host on {ev.control_passes} variants; "
                 f"not applicable on {len(ev.control_not_applicable)} "
                 f"({', '.join(ev.control_not_applicable) or 'none'})")
    if ev.blind_confirmed:
        lines.append("- blind variants whose fetch was confirmed out of band: "
                     + ", ".join(ev.blind_confirmed))
    if ev.measured_not_declared:
        lines.append("- bypasses measured beyond those declared (informational): "
                     + "; ".join(f"{k}: {', '.join(f.split('_')[0] for f in v)}"
                                 for k, v in sorted(ev.measured_not_declared.items())))
    problems = ev.problems
    if problems:
        lines.append("")
        lines.append("**Problems that must be resolved before these numbers are used:**")
        lines += [f"- {p}" for p in problems]
    else:
        lines.append("- no label, declaration or control mismatches")
    return "\n".join(lines)


def full_report(corpus: Corpus, ev: DynamicEvaluation, probe_result: dict) -> str:
    counts = corpus.counts()
    lab_lines = []
    for run in probe_result.get("runs", []):
        lab = run.get("lab", {})
        lab_lines.append(f"- `{run.get('app')}`: {lab.get('ready_line', '?')} "
                         f"(pid {lab.get('pid')}, port held by pid {lab.get('port_owner_pid')})")
    isolation = probe_result.get("isolation", {})
    iso_lines = [f"- `{k}`: {v}" for k, v in sorted(isolation.items())]

    return "\n".join([
        "# SSReFuse dynamic evaluation",
        "",
        "## What was measured",
        "",
        f"- corpus: {counts['variants']} variants across {counts['apps']} application(s), "
        f"{counts['vulnerable']} labelled vulnerable, {counts['safe']} labelled safe",
        f"- payload catalog: {len(catalog.FAMILIES)} families, "
        f"{len(catalog.ATTACK_FAMILIES)} of them attacks, "
        f"{len(catalog.INSTRUMENT_FAMILIES)} instrument, 1 control",
        *lab_lines,
        "",
        "### Sandbox isolation controls",
        "",
        "Both of these must fail for a run to proceed; they are the negative",
        "control for the testbed itself.",
        "",
        *iso_lines,
        "",
        integrity_section(ev),
        "",
        "## Bypass matrix",
        "",
        bypass_matrix(corpus, ev),
        "",
        "## Which technique defeated how many variants",
        "",
        family_effectiveness(corpus, ev),
        "",
        "## Guards, grouped",
        "",
        guard_summary(corpus, ev),
        "",
    ])


def detector_table(evaluations) -> str:
    lines = ["| detector | status | candidates | attributed | unattributed | "
             "via shared | TP | FP | FN | TN | precision | recall | F1 |",
             "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for ev in evaluations:
        s = ev.against_declared
        lines.append(
            f"| {ev.detector} | {ev.status} | {ev.candidates} | {ev.attributed} | "
            f"{len(ev.unattributed)} | {ev.via_shared} | {s.tp} | {s.fp} | {s.fn} | {s.tn} | "
            f"{s.fmt(s.precision)} | {s.fmt(s.recall)} | {s.fmt(s.f1)} |")
    return "\n".join(lines)


def detector_errors(evaluations) -> str:
    lines = []
    for ev in evaluations:
        parts = []
        if ev.false_positives:
            parts.append("false positives on " + ", ".join(sorted(ev.false_positives)))
        if ev.false_negatives:
            parts.append("missed " + ", ".join(sorted(ev.false_negatives)))
        if ev.unattributed:
            where = sorted({f"{c.file.split('/')[-1]}:{c.line}" for c in ev.unattributed})
            parts.append(f"{len(ev.unattributed)} finding(s) outside any labelled region "
                         f"({', '.join(where[:6])}{', ...' if len(where) > 6 else ''})")
        lines.append(f"- **{ev.detector}**: " + ("; ".join(parts) if parts else
                     "no false positives, no misses, every finding attributed"))
    return "\n".join(lines)


def per_variant_detection(corpus, evaluations) -> str:
    header = "| variant | label | guard | " + " | ".join(ev.detector for ev in evaluations) + " |"
    lines = [header, "|" + "---|" * (len(evaluations) + 3)]
    for variant in corpus.variants:
        guard = ", ".join(g.split("_")[0] for g in variant.guards) or "none"
        marks = []
        for ev in evaluations:
            count = ev.per_variant_counts.get(variant.id, 0)
            if count and variant.label == "safe":
                marks.append(f"`FP`({count})")
            elif count:
                marks.append(f"`hit`({count})")
            elif variant.label == "vulnerable":
                marks.append("`MISS`")
            else:
                marks.append("`-`")
        lines.append(f"| {variant.id} | {variant.label} | {guard} | " + " | ".join(marks) + " |")
    return "\n".join(lines)


def judge_table(judgements) -> str:
    lines = ["| location | detector | verdict | confidence | same value checked "
             "and fetched | rounds | slice lines | families named |",
             "|---|---|---|---|---|---|---|---|"]
    for j in sorted(judgements, key=lambda x: (x.file, x.line)):
        same = {True: "yes", False: "no", None: "unknown"}.get(
            j.same_value_validated_and_fetched, str(j.same_value_validated_and_fetched))
        families = ", ".join(f.split("_")[0] for f in j.bypass_families) or "-"
        flag = " (mock)" if j.is_mock else ""
        lines.append(f"| {j.file.split('/')[-1]}:{j.line} | {j.detector} | "
                     f"{j.verdict}{flag} | {j.confidence:.2f} | {same} | {j.rounds} | "
                     f"{j.slice_lines} | {families} |")
    return "\n".join(lines)


def strategy_table(strategies) -> str:
    lines = ["| strategy | scored over | flagged | TP | FP | FN | TN | precision | "
             "recall | F1 | settled by the prober |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for st in strategies:
        s = st.scores
        lines.append(f"| {st.name} | all variants | {len(st.flagged)} | {s.tp} | "
                     f"{s.fp} | {s.fn} | {s.tn} | {s.fmt(s.precision)} | "
                     f"{s.fmt(s.recall)} | {s.fmt(s.f1)} | "
                     f"{len(st.resolved_by_prober)} |")
        sub = getattr(st, "scores_judge_decided", None)
        if sub is not None and (sub.tp + sub.fp + sub.fn + sub.tn):
            lines.append(f"| {st.name} | only the {len(st.judge_decided)} the judge "
                         f"decided itself | - | {sub.tp} | {sub.fp} | {sub.fn} | "
                         f"{sub.tn} | {sub.fmt(sub.precision)} | "
                         f"{sub.fmt(sub.recall)} | {sub.fmt(sub.f1)} | 0 |")
    return "\n".join(lines)


def strategy_notes(strategies) -> str:
    lines = []
    for st in strategies:
        lines.append(f"- **{st.name}**: {st.description}")
        if st.resolved_by_prober:
            lines.append(f"    - the judge declined to decide these and the prober "
                         f"settled them: {', '.join(st.resolved_by_prober)}")
        if st.undecided:
            lines.append(f"    - left undecided: {', '.join(st.undecided)}")
        for note in st.notes:
            lines.append(f"    - {note}")
    return "\n".join(lines)
