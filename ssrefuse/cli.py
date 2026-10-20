"""Command line entry point.

Pipeline stages are separate commands so each can be re-run on its own, and
``all`` chains them in the only order the evidence allows: validate the corpus,
measure dynamically, scan statically, then score. Scoring refuses to run on a
detector whose positive control came back empty, and on a corpus that does not
validate, because both failures produce confident-looking zeros.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ssrefuse import testbed_spec as spec
from ssrefuse.corpus import REPO_ROOT, Corpus
from ssrefuse.harness.payloads import FAMILY_BY_ID, summary as catalog_summary

RESULTS = REPO_ROOT / "results"
PROBE_RESULT = RESULTS / "probe" / "result.json"
STATIC_RESULT = RESULTS / "static-runs.json"
JUDGE_RESULT = RESULTS / "llm-judgements.json"
VENV_PYTHON = REPO_ROOT / ".venv" / "bin" / "python"


def _python_for_labs(explicit: str | None) -> str:
    if explicit:
        return explicit
    return str(VENV_PYTHON) if VENV_PYTHON.exists() else sys.executable


def cmd_validate(args) -> int:
    corpus = Corpus()
    report = corpus.validate(set(FAMILY_BY_ID))
    print(report.render())
    print(f"counts: {corpus.counts()}")
    print(catalog_summary())
    if report.problems:
        print("\ncorpus does not validate", file=sys.stderr)
        return 1
    return 0


def cmd_selftest(args) -> int:
    from ssrefuse.harness.sandbox import run_in_sandbox
    result = run_in_sandbox({"job": "selftest"}, RESULTS / "selftest")
    if not result.get("ok"):
        print(f"selftest failed: {result.get('error')}", file=sys.stderr)
        print(result.get("traceback", "")[-2000:], file=sys.stderr)
        return 1
    print("sandbox isolation controls (both must fail for the run to proceed):")
    for key, value in sorted(result["isolation"].items()):
        print(f"  {key:34} {value}")
    print("\ntestbed services:")
    for key, value in sorted(result["testbed"].items()):
        print(f"  {key:34} {value}")
    print("\nprobes from inside the sandbox:")
    for key, value in result["probes"].items():
        print(f"  {key:22} {json.dumps(value)}")
    return 0


def cmd_probe(args) -> int:
    from ssrefuse.harness.sandbox import run_in_sandbox
    plan = {"job": "probe", "python": _python_for_labs(args.python)}
    if args.apps:
        plan["apps"] = args.apps
    result = run_in_sandbox(plan, RESULTS / "probe", timeout=args.timeout)
    if not result.get("ok"):
        print(f"probe failed: {result.get('error')}", file=sys.stderr)
        print(result.get("traceback", "")[-2000:], file=sys.stderr)
        return 1
    for run in result["runs"]:
        lab = run["lab"]
        print(f"{run['app']}: {lab['ready_line']} "
              f"(pid {lab['pid']}, port held by {lab['port_owner_pid']})")
        print(f"  probe rows: {len(run['outcomes'])}")
    print(f"\nwrote {PROBE_RESULT}")
    return 0


def cmd_scan(args) -> int:
    from ssrefuse.detectors.semgrep_runner import run_all
    targets = [Path(t) for t in args.targets] if args.targets else None
    runs = run_all(targets=targets)
    STATIC_RESULT.parent.mkdir(parents=True, exist_ok=True)
    STATIC_RESULT.write_text(json.dumps([r.as_dict() for r in runs], indent=2))
    failed = False
    for run in runs:
        print(f"{run.detector:14} {run.status():50} candidates={len(run.candidates):3} "
              f"control={run.control_findings} files={run.scanned_files} "
              f"{run.duration_s:.1f}s")
        for error in run.errors[:5]:
            print(f"    {error[:160]}")
        failed = failed or not run.usable
    print(f"\nwrote {STATIC_RESULT}")
    return 1 if failed else 0


def _load_static_runs() -> list:
    from ssrefuse.detectors.base import Candidate, DetectorRun
    runs = []
    for raw in json.loads(STATIC_RESULT.read_text()):
        run = DetectorRun(detector=raw["detector"], config=raw["config"],
                          control_findings=raw["control_findings"],
                          errors=raw["errors"], duration_s=raw["duration_s"],
                          scanned_files=raw["scanned_files"],
                          control_file=raw.get("control_file", ""))
        run.candidates = [Candidate(**item) for item in raw["candidates"]]
        runs.append(run)
    return runs


def cmd_judge(args) -> int:
    from ssrefuse.detectors.llm_judge import LLMJudge
    from ssrefuse.llm.cache import ResponseCache
    from ssrefuse.llm.client import LLMClient, LLMUnavailable

    if not STATIC_RESULT.exists():
        print(f"no static results at {STATIC_RESULT}; run `ssrefuse scan` first",
              file=sys.stderr)
        return 1
    runs = {run.detector: run for run in _load_static_runs()}
    source = runs.get(args.candidates_from)
    if source is None:
        print(f"no detector named {args.candidates_from!r} in {STATIC_RESULT}; "
              f"have: {', '.join(sorted(runs))}", file=sys.stderr)
        return 1
    if not source.usable:
        print(f"candidate set comes from an unusable run ({source.status()}); "
              f"refusing to judge", file=sys.stderr)
        return 1

    client = LLMClient(provider=args.provider, model=args.model,
                       temperature=args.temperature,
                       cache=ResponseCache(enabled=not args.no_cache))
    try:
        client.check_ready()
    except LLMUnavailable as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if client.is_mock:
        print("WARNING: provider is 'mock'. The output is placeholder text, it is "
              "labelled as such, and it must not be read as a measurement.",
              file=sys.stderr)

    corpus = Corpus()
    judge = LLMJudge(client, max_rounds=args.rounds,
                     strip_comments=not args.keep_comments)
    judgements = judge.judge_candidates(source.candidates, corpus)

    payload = {"client": client.describe(),
               "candidates_from": args.candidates_from,
               "max_rounds": args.rounds,
               "comments_stripped": not args.keep_comments,
               "judgements": [j.as_dict() for j in judgements]}
    JUDGE_RESULT.parent.mkdir(parents=True, exist_ok=True)
    JUDGE_RESULT.write_text(json.dumps(payload, indent=2))

    counts: dict[str, int] = {}
    for judgement in judgements:
        counts[judgement.verdict] = counts.get(judgement.verdict, 0) + 1
    print(f"judged {len(judgements)} location(s) from {args.candidates_from}: "
          + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    multi = [j for j in judgements if j.rounds > 1]
    print(f"second round used on {len(multi)} location(s)")
    errors = [j for j in judgements if j.parse_error]
    if errors:
        print(f"{len(errors)} answer(s) needed repair or could not be parsed:")
        for judgement in errors[:5]:
            print(f"  {judgement.file}:{judgement.line} {judgement.parse_error}")
    print(f"client: {client.describe()}")
    print(f"wrote {JUDGE_RESULT}")
    return 0


def _load_judgements():
    from ssrefuse.detectors.llm_judge import Judgement
    if not JUDGE_RESULT.exists():
        return None, []
    payload = json.loads(JUDGE_RESULT.read_text())
    fields = set(Judgement.__dataclass_fields__)
    judgements = [Judgement(**{k: v for k, v in item.items() if k in fields})
                  for item in payload["judgements"]]
    return payload, judgements


def cmd_report(args) -> int:
    from ssrefuse.evaluation.dynamic import evaluate
    from ssrefuse.evaluation.static import evaluate_runs
    from ssrefuse.reporting import tables

    corpus = Corpus()
    validation = corpus.validate(set(FAMILY_BY_ID))
    if validation.problems:
        print(validation.render(), file=sys.stderr)
        print("refusing to report on a corpus that does not validate", file=sys.stderr)
        return 1

    if not PROBE_RESULT.exists():
        print(f"no probe result at {PROBE_RESULT}; run `ssrefuse probe` first", file=sys.stderr)
        return 1
    probe_result = json.loads(PROBE_RESULT.read_text())
    dyn = evaluate(corpus, probe_result)

    sections = [tables.full_report(corpus, dyn, probe_result)]

    if STATIC_RESULT.exists():
        static_runs = _load_static_runs()
        static_evals = evaluate_runs(corpus, static_runs, dyn)
        sections += [
            "## Static detectors",
            "",
            "Scored against the declared labels. Every run includes a positive",
            "control file in the same invocation; a run whose control produced no",
            "finding is marked unusable and its numbers are not comparable.",
            "",
            tables.detector_table(static_evals),
            "",
            "### Where each detector was wrong",
            "",
            tables.detector_errors(static_evals),
            "",
            "### Per-variant detection",
            "",
            tables.per_variant_detection(corpus, static_evals),
            "",
        ]
    else:
        sections += ["## Static detectors", "",
                     "Not run. `ssrefuse scan` has not been executed, so this report",
                     "says nothing about static detection.", ""]

    payload, judgements = _load_judgements()
    if judgements:
        from ssrefuse.detectors.fuse import run_strategies
        runs = {run.detector: run for run in _load_static_runs()} \
            if STATIC_RESULT.exists() else {}
        strategies = run_strategies(corpus, runs, judgements, dyn)
        client = payload.get("client", {})
        mock = client.get("is_mock")
        sections += [
            "## LLM judge and fusion",
            "",
            (f"**These rows come from the mock provider: no model was called, the "
             f"answers are placeholder text, and the numbers are not results.**\n"
             if mock else
             f"Provider `{client.get('provider')}`, model `{client.get('model')}`, "
             f"temperature {client.get('temperature')}, candidates from "
             f"`{payload.get('candidates_from')}`, up to "
             f"{payload.get('max_rounds')} round(s) per location, comments "
             f"{'kept' if not payload.get('comments_stripped') else 'stripped'} "
             f"before slicing."),
            "",
            tables.judge_table(judgements),
            "",
            "### Strategy comparison",
            "",
            tables.strategy_table(strategies),
            "",
            tables.strategy_notes(strategies),
            "",
        ]
    else:
        sections += ["## LLM judge and fusion", "",
                     "Not run. `ssrefuse judge` has not been executed, so this",
                     "report says nothing about LLM-assisted detection.", ""]

    output = Path(args.output) if args.output else RESULTS / "report.md"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(sections))
    print(f"wrote {output}")
    if dyn.problems:
        print("\nunresolved problems:", file=sys.stderr)
        for problem in dyn.problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    return 0


def cmd_all(args) -> int:
    steps = [cmd_validate, cmd_probe, cmd_scan]
    if getattr(args, "with_judge", False):
        steps.append(cmd_judge)
    steps.append(cmd_report)
    for step in steps:
        code = step(args)
        if code != 0:
            print(f"\nstopped at {step.__name__}", file=sys.stderr)
            return code
        print()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ssrefuse",
        description="SSRF detection: hermetic lab, bypass matrix, static and LLM detectors")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("validate", help="check the corpus against its source markers").set_defaults(
        func=cmd_validate)
    sub.add_parser("selftest", help="build the sandbox and prove it is hermetic").set_defaults(
        func=cmd_selftest)

    probe = sub.add_parser("probe", help="run every payload against every variant")
    probe.add_argument("--apps", nargs="*", help="limit to these applications")
    probe.add_argument("--python", help="interpreter used to start the labs")
    probe.add_argument("--timeout", type=float, default=1800.0)
    probe.set_defaults(func=cmd_probe)

    scan = sub.add_parser("scan", help="run the static detectors")
    scan.add_argument("targets", nargs="*", help="paths to scan (default: corpus/labs)")
    scan.set_defaults(func=cmd_scan)

    judge = sub.add_parser("judge", help="run the LLM judge over static candidates")
    judge.add_argument("--provider", default="deepseek",
                       help="deepseek (default), openai-compatible, or mock")
    judge.add_argument("--model", default=None,
                       help="deepseek-chat or deepseek-reasoner")
    judge.add_argument("--rounds", type=int, default=2,
                       help="maximum rounds; >1 lets the judge ask for more code")
    judge.add_argument("--candidates-from", default="inventory",
                       help="which detector run supplies the candidate set")
    judge.add_argument("--temperature", type=float, default=0.0)
    judge.add_argument("--no-cache", action="store_true")
    judge.add_argument("--keep-comments", action="store_true",
                       help="do not strip comments and docstrings; for measuring "
                            "how much the lab's own documentation inflates the score")
    judge.set_defaults(func=cmd_judge)

    report = sub.add_parser("report", help="score everything measured so far")
    report.add_argument("-o", "--output")
    report.set_defaults(func=cmd_report)

    every = sub.add_parser("all", help="validate, probe, scan, report")
    every.add_argument("--apps", nargs="*")
    every.add_argument("--python")
    every.add_argument("--timeout", type=float, default=1800.0)
    every.add_argument("-o", "--output")
    every.add_argument("--with-judge", action="store_true",
                       help="also run the LLM judge (needs an API key)")
    every.add_argument("--provider", default="deepseek")
    every.add_argument("--model", default=None)
    every.add_argument("--rounds", type=int, default=2)
    every.add_argument("--candidates-from", default="inventory")
    every.add_argument("--temperature", type=float, default=0.0)
    every.add_argument("--no-cache", action="store_true")
    every.add_argument("--keep-comments", action="store_true")
    every.add_argument("targets", nargs="*")
    every.set_defaults(func=cmd_all)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
