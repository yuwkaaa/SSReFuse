"""Markdown rendering of the evaluation tables.

The report prints the raw counts next to anything derived from them. A matrix
that shows only verdict symbols cannot be checked by a reader, so every table
carries the totals it was computed from.
"""
from __future__ import annotations

from ssrefuse.corpus import REPO_ROOT, Corpus
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
    """One row per family, with the axis it belongs to and how many concrete
    values stand behind the count. A family that defeated nothing is kept in
    the table: a measured zero against twenty values is a result, and dropping
    it would turn the table into a list of what happened to work."""
    vulnerable = [v for v in corpus.variants if v.label == "vulnerable"]
    lines = ["| family | axis | values | technique | variants bypassed | "
             "of vulnerable variants |", "|---|---|---|---|---|---|"]
    for family_id in ev.families:
        family = catalog.FAMILY_BY_ID[family_id]
        values = len(family.url_values) + len(family.host_values) + len(family.path_values)
        count = ev.family_count(family_id)
        lines.append(f"| {family_id} | {family.axis} | {values} | {family.title} | "
                     f"{count} | {len(vulnerable)} |")
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


def cross_language_table(corpus: Corpus, ev: DynamicEvaluation) -> str:
    """The same guard, in two runtimes, measured.

    Variants are grouped by the guard set *and* the injection shape, because a
    path-injection row and a URL-injection row are not comparable even when the
    guard is written the same way. Only groups that exist in more than one
    language are printed; a guard that only one lab implements says nothing
    about either runtime and is left out rather than shown with an empty half.

    The last column is the point of the table: a family that worked against one
    language and not the other is a fact about the runtime, not about the guard.
    """
    groups: dict[tuple, dict[str, list]] = {}
    for variant in corpus.variants:
        key = (tuple(sorted(variant.guards)) or ("(none)",), variant.payload_kind)
        groups.setdefault(key, {}).setdefault(variant.lang, []).append(variant)

    lines = ["| guard | injection | language | variants | sinks | families that worked | "
             "worked here only |", "|---|---|---|---|---|---|---|"]
    printed = 0
    for (guards, kind), by_lang in sorted(groups.items()):
        if len(by_lang) < 2:
            continue
        printed += 1
        worked = {lang: sorted({fam for v in variants
                                for (vid, fam), cell in ev.cells.items()
                                if vid == v.id and cell.is_bypass and fam in ev.families})
                  for lang, variants in by_lang.items()}
        for lang, variants in sorted(by_lang.items()):
            others = set().union(*(set(worked[other]) for other in worked if other != lang))
            only = sorted(set(worked[lang]) - others)
            sinks = ", ".join(sorted({v.sink for v in variants}))
            lines.append(
                f"| {', '.join(g.split('_')[0] for g in guards)} | {kind} | {lang} | "
                f"{', '.join(v.id for v in variants)} | {sinks} | "
                f"{', '.join(f.split('_')[0] for f in worked[lang]) or 'none reproduced'} | "
                f"{', '.join(f.split('_')[0] for f in only) or '-'} |")
    if not printed:
        return "Only one language in the corpus, so there is nothing to compare."
    return "\n".join(lines)


def bypass_versus_rule(corpus: Corpus, ev: DynamicEvaluation, evaluations) -> str:
    """The deliverable the brief asks for: bypass technique against rule.

    The two tables this project already had do not answer it. The bypass
    matrix is variant-by-family -- which technique got through. The detector
    table is detector-by-variant -- which route a rule flagged. The question
    here is a third one: *of the variants a technique actually defeated, how
    many did each rule flag?*

    Reading it needs one caution, printed with the table rather than left to
    the reader. A static rule does not see a payload at all. It flags a code
    location, and the location is the same whichever technique defeats it. So
    a high score in this table does not mean the rule understands the
    technique -- it means the technique happens to defeat routes that the rule
    flags for unrelated reasons. The column that carries the real information
    is the last one: a technique whose variants no rule flags is a technique
    that static analysis is, on this corpus, blind to.
    """
    if not evaluations:
        return "No static detector run, so there is nothing to compare bypasses against."

    usable = [e for e in evaluations if e.usable]
    if not usable:
        return ("Every detector run is unusable, so this table is omitted rather "
                "than printed with numbers that cannot be compared.")

    header = ("| technique | axis | variants it defeated | "
              + " | ".join(f"flagged by {e.detector}" for e in usable)
              + " | missed by every rule |")
    lines = [header, "|" + "---|" * (len(usable) + 4)]

    for family_id in ev.families:
        family = catalog.FAMILY_BY_ID[family_id]
        defeated = {vid for (vid, fam), cell in ev.cells.items()
                    if fam == family_id and cell.is_bypass}
        if not defeated:
            lines.append(f"| {family_id} | {family.axis} | 0 | "
                         + " | ".join("n/a" for _ in usable)
                         + " | n/a |")
            continue
        cells = []
        missed_by_all = set(defeated)
        for ev_detector in usable:
            hit = defeated & ev_detector.flagged
            missed_by_all -= ev_detector.flagged
            cells.append(f"{len(hit)}/{len(defeated)}")
        lines.append(f"| {family_id} | {family.axis} | {len(defeated)} | "
                     + " | ".join(cells)
                     + f" | {', '.join(sorted(missed_by_all)) or 'none'} |")

    lines += ["",
              "`n/a` marks a technique that defeated no variant in this run: there is",
              "no set of routes for a rule to have flagged, so a score there would be",
              "an artefact. Those rows are kept because a measured zero over several",
              "concrete values is a result.",
              "",
              "A cell reads `flagged / defeated`. It is **not** a measure of whether the",
              "rule understands the technique: a static rule matches a code location,",
              "and that location does not change with the payload. The informative",
              "column is the last one."]
    return "\n".join(lines)


def sink_inventory_table(entries, status: str = "") -> str:
    """Found, missed and unmarked, per file, never merged.

    `missed` is the number that matters: it is the part of the attack surface
    the rule is blind to, in a language where nothing in this project can run
    a proof. `unmarked` is not an error -- it may be a real sink nobody
    marked -- and it is listed with its line numbers so a person can decide,
    rather than being folded into a score it did not earn.
    """
    from ssrefuse.evaluation import sinks

    if not entries:
        return ("The static-only corpus is empty or was not scanned, so nothing "
                "is claimed about PHP, Java or the client libraries.")
    lines = []
    if status and status != "ok":
        lines += [f"**This run is {status}. The numbers below are not comparable.**", ""]
    lines += ["| file | language | marked sinks | found | missed | reported without a marker |",
              "|---|---|---|---|---|---|"]
    for entry in entries:
        lines.append(
            f"| `{entry.file}` | {entry.language} | {entry.expected} | "
            f"{len(entry.found)} | {', '.join(entry.missed) or 'none'} | "
            f"{', '.join(f'line {n}' for n in entry.unmarked) or 'none'} |")
    counts = sinks.totals(entries)
    lines.append(f"| **total** | | **{counts['expected']}** | **{counts['found']}** | "
                 f"**{counts['missed']}** | **{counts['unmarked']}** |")
    lines += ["",
              "A marked sink counts as found when a rule reported a line within four",
              "lines of the marker, because a call can sit below its own arguments.",
              "The marker names are in the sources under `corpus/static_only/`, so a",
              "missed row names the construct rather than a line number that moves.",
              "",
              "**Read this number with the circularity in mind.** The rules and these",
              "files were written in the same sitting, so a high score partly measures",
              "that agreement rather than the rules' reach. It is reported because the",
              "alternative -- saying nothing about PHP and Java -- is worse, and",
              "because the number is falsifiable in the one direction that matters: a",
              "sink added here by someone who did not write the rules, or taken from a",
              "real codebase, moves `missed` off zero the moment the rules do not",
              "cover it. Until that happens the honest reading is \"the rules cover the",
              "constructs this project thought of\", not \"the rules cover PHP\"."]
    return "\n".join(lines)


def ablation_table(arms, corpus, runs, dyn) -> str:
    """One row per judge run, with what it decided and what it cost.

    The arms differ in exactly one thing -- the thinking budget -- because the
    model is held fixed. That is what lets a difference in the numbers have
    one cause, and it is why the cost columns sit beside the score columns:
    "the thinking arm scored higher" and "scored higher for twelve times the
    output tokens" are different findings, and only one of them is a reason to
    turn thinking on.
    """
    from ssrefuse.detectors.fuse import run_strategies

    if not arms:
        return "No judge run on disk."

    rows = []
    for name, payload, judgements in arms:
        client = payload.get("client", {})
        if client.get("is_mock"):
            continue
        strategies = {s.name: s for s in run_strategies(corpus, runs, judgements, dyn)}
        llm = strategies.get("llm_only")
        cascade = strategies.get("fuse_cascade")
        counts: dict[str, int] = {}
        for j in judgements:
            counts[j.verdict] = counts.get(j.verdict, 0) + 1
        flagged, judged_ids = set(), {}
        for judgement in judgements:
            for variant in corpus.attribute_all(
                    judgement.file.replace(str(REPO_ROOT) + "/", ""), judgement.line):
                judged_ids[variant.id] = judgement
                if judgement.verdict == "vulnerable":
                    flagged.add(variant.id)
        per_language: dict[str, dict] = {}
        for variant in corpus.variants:
            if variant.id not in judged_ids:
                continue
            slot = per_language.setdefault(
                variant.lang, {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
            hit, vulnerable = variant.id in flagged, variant.label == "vulnerable"
            slot["tp" if (hit and vulnerable) else "fp" if hit
                 else "fn" if vulnerable else "tn"] += 1
        for slot in per_language.values():
            hits = slot["tp"] + slot["fp"]
            real = slot["tp"] + slot["fn"]
            slot["p"] = f"{slot['tp'] / hits:.3f}" if hits else "n/a"
            slot["r"] = f"{slot['tp'] / real:.3f}" if real else "n/a"

        rows.append({
            "per_language": per_language,
            "false_positives": sorted(v.id for v in corpus.variants
                                      if v.id in flagged and v.label == "safe"),
            "declined": sorted(vid for vid, j in judged_ids.items()
                               if j.verdict == "needs_dynamic_test"),
            "effort": payload.get("reasoning_effort", client.get("reasoning_effort", "?")),
            "model": client.get("model", "?"),
            "calls": client.get("calls", 0),
            "tin": client.get("tokens_in", 0),
            "tout": client.get("tokens_out", 0),
            "think": client.get("reasoning_tokens", 0),
            "seconds": payload.get("duration_s"),
            "vuln": counts.get("vulnerable", 0),
            "safe": counts.get("safe", 0),
            "undecided": counts.get("needs_dynamic_test", 0),
            "rounds2": sum(1 for j in judgements if j.rounds > 1),
            "parse": sum(1 for j in judgements if j.parse_error),
            "llm": llm,
            "cascade": cascade,
            "sample": payload.get("is_sample", False),
            "judged": payload.get("candidates_judged", len(judgements)),
        })
    if not rows:
        return "Only mock runs on disk, so there is nothing to compare."

    lines = ["**What each arm decided.** Scored against the declared labels, over the",
             "candidate set the inventory tier proposed.", "",
             "| thinking | locations | vulnerable | safe | needs_dynamic_test | "
             "2nd round | unparsable |", "|---|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| `{r['effort']}` | {r['judged']}{' (sample)' if r['sample'] else ''} "
                     f"| {r['vuln']} | {r['safe']} | {r['undecided']} | {r['rounds2']} "
                     f"| {r['parse']} |")

    lines += ["", "**What each arm scored.** `llm_only` is the judge on its own.",
              "`fuse_cascade judge-decided` excludes the cells the prober settled, where",
              "the verdict and the label come from the same measurement.", "",
              "| thinking | llm_only P / R / F1 | cascade P / R / F1 | "
              "cascade, judge-decided only |", "|---|---|---|---|"]
    for r in rows:
        def fmt(scores):
            if scores is None:
                return "n/a"
            return (f"{scores.fmt(scores.precision)} / {scores.fmt(scores.recall)} "
                    f"/ {scores.fmt(scores.f1)}")
        llm_s = r["llm"].scores if r["llm"] else None
        cas_s = r["cascade"].scores if r["cascade"] else None
        cas_j = r["cascade"].scores_judge_decided if r["cascade"] else None
        lines.append(f"| `{r['effort']}` | {fmt(llm_s)} | {fmt(cas_s)} | {fmt(cas_j)} |")

    lines += ["", "**What each arm cost.**", "",
              "| thinking | calls | tokens in | tokens out | of which reasoning | seconds |",
              "|---|---|---|---|---|---|"]
    for r in rows:
        secs = f"{r['seconds']:.0f}" if r["seconds"] else "not recorded"
        lines.append(f"| `{r['effort']}` | {r['calls']} | {r['tin']:,} | {r['tout']:,} "
                     f"| {r['think']:,} | {secs} |")

    base = next((r for r in rows if r["effort"] in ("off", "none")), None)
    if base and len(rows) > 1:
        for r in rows:
            if r is base:
                continue
            factor = r["tout"] / base["tout"] if base["tout"] else 0
            moved = r["vuln"] - base["vuln"]
            lines += ["",
                      f"Against the `{base['effort']}` arm, `{r['effort']}` changed the "
                      f"vulnerable count by {moved:+d} and spent {factor:.1f} times the "
                      f"output tokens."]
    lines += ["", "**Split by language**, because the JavaScript slicer is a character",
              "scanner and the Python one walks an AST. A single row would hide which",
              "half carries the error.", "",
              "| thinking | language | TP | FP | FN | TN | P | R |", "|---|---|---|---|---|---|---|---|"]
    for r in rows:
        for lang, s in sorted(r["per_language"].items()):
            lines.append(f"| `{r['effort']}` | {lang} | {s['tp']} | {s['fp']} | {s['fn']} "
                         f"| {s['tn']} | {s['p']} | {s['r']} |")

    lines += ["", "**Where each arm was wrong.** A declined location counts against recall",
              "and is listed separately from a wrong answer, because \"I cannot tell from",
              "this slice\" is the behaviour the prompt asks for and a wrong verdict is not.",
              "", "| thinking | called a safe route vulnerable | declined |", "|---|---|---|"]
    for r in rows:
        lines.append(f"| `{r['effort']}` | {', '.join(r['false_positives']) or 'none'} "
                     f"| {', '.join(r['declined']) or 'none'} |")

    lines += ["",
              "`off` disables thinking and is the real non-thinking arm. `none` would send",
              "no parameter at all, which was measured to leave thinking ON by default, so",
              "it is not a baseline and is not used as one here."]
    return "\n".join(lines)


def catalog_coverage() -> str:
    """What the catalog crosses, as numbers rather than as a claim.

    "Does this include every payload" has no yes: there is no finite list of
    ways to write an address or wrap an authority. What can be stated is which
    axes the catalog varies and how far along each one it goes, which is a
    thing a reader can check and a thing the next person can extend one line
    at a time.
    """
    axis_note = {
        "spelling": "the same internal address, written differently",
        "target": "a different internal service to reach",
        "wrapper": "the allowlisted name present without being the authority",
        "scheme": "a handler other than http",
        "flow": "the request changes destination after the guard ran",
        "control": "must succeed; not an attack",
    }
    lines = ["| axis | what it varies | families | concrete values |", "|---|---|---|---|"]
    coverage = catalog.axis_coverage()
    for axis in catalog.AXES:
        counts = coverage[axis]
        lines.append(f"| {axis} | {axis_note[axis]} | {counts['families']} | "
                     f"{counts['values']} |")
    total_families = sum(c["families"] for c in coverage.values())
    total_values = sum(c["values"] for c in coverage.values())
    lines.append(f"| **total** | | **{total_families}** | **{total_values}** |")

    lines += ["", "Internal targets the catalog can aim at, and what reaching one",
              "is worth. The right-hand column is why the target is in the list at",
              "all: on its own an SSRF is \"the server fetched a URL\", and the",
              "severity is the next hop. That hop is **not** exercised here -- the",
              "harness measures reachability and states the escalation rather than",
              "performing it -- so the column is a statement about the software",
              "each service imitates, not a result.",
              "",
              "| service | authority | reaching it leads to |", "|---|---|---|"]
    for target in catalog.TARGETS:
        lines.append(f"| {target.title} | `{target.authority}` | "
                     f"{target.chain or 'not recorded'} |")
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
        "## What the catalog varies",
        "",
        catalog_coverage(),
        "",
        "## Which technique defeated how many variants",
        "",
        family_effectiveness(corpus, ev),
        "",
        "## Guards, grouped",
        "",
        guard_summary(corpus, ev),
        "",
        "## The same guard in two runtimes",
        "",
        "Rows that exist in only one language are left out. Where a family",
        "worked against one runtime and not the other, the runtime is the",
        "reason: new URL() canonicalises numeric and percent-encoded",
        "authorities before a denylist sees them, fetch() refuses a URL that",
        "carries credentials, and fetch() follows redirects where http.get()",
        "and requests-with-allow_redirects-off do not.",
        "",
        cross_language_table(corpus, ev),
        "",
        "Within the JavaScript lab, js-007 and js-008 are the controlled",
        "version of the same question: identical denylist, identical sink,",
        "one parsing the URL with the legacy parser and the other with the",
        "WHATWG parser. The guard table above gives them as G13 and G2.",
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
