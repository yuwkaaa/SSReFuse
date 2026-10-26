"""Corpus loading and validation.

Ground truth lives in corpus/ground-truth.yaml; the line ranges that attribute a
static-analysis finding to a variant live in the lab sources as
``@ssrefuse:begin/end`` markers. Keeping them apart means editing a lab cannot
silently invalidate a stored range, and it means the two sides can be
cross-checked -- which ``validate`` does, reporting every mismatch in both
directions rather than quietly using the intersection.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
GROUND_TRUTH = REPO_ROOT / "corpus" / "ground-truth.yaml"

BEGIN_RE = re.compile(r"^\s*(?:#|//|/\*)\s*@ssrefuse:begin\s+([\w.-]+)")
END_RE = re.compile(r"^\s*(?:#|//|/\*)\s*@ssrefuse:end\s+([\w.-]+)")


@dataclass
class Variant:
    id: str
    app: str
    lang: str
    file: str
    sink: str
    guards: list[str]
    flow: str
    observability: str
    label: str
    entry: dict
    bypasses_declared: list[str]
    why_safe: str = ""
    notes: str = ""
    no_sink: bool = False
    no_user_input: bool = False
    uses_shared: list[str] = field(default_factory=list)
    line_start: int = 0
    line_end: int = 0
    shared_spans: dict[str, tuple[int, int]] = field(default_factory=dict)

    @property
    def payload_kind(self) -> str:
        if "steps" in self.entry:
            for step in self.entry["steps"]:
                if "payload_kind" in step:
                    return step["payload_kind"]
            return "none"
        return self.entry.get("payload_kind", "none")

    def covers(self, path: str, line: int) -> bool:
        """True when a finding at this location belongs to this variant."""
        if Path(path).name != Path(self.file).name:
            return False
        if self.line_start <= line <= self.line_end:
            return True
        return any(start <= line <= end for start, end in self.shared_spans.values())

    def covers_directly(self, path: str, line: int) -> bool:
        return (Path(path).name == Path(self.file).name
                and self.line_start <= line <= self.line_end)


@dataclass
class App:
    name: str
    lang: str
    file: str
    start: list[str]
    ready_marker: str
    framework: str = ""
    # How the ready marker is matched in the lab's log. "prefix" is the
    # default and the stricter one: the lab prints the marker itself, at the
    # start of a line. "contains" exists for a server that prints its own
    # banner instead -- PHP's built-in server timestamps every line, so its
    # marker can never be at column zero. Declared per app rather than
    # loosened for everyone, because `in` would also match a line that merely
    # quotes the marker, such as an error message about it.
    ready_match: str = "prefix"
    min_runtime: str = ""


@dataclass
class ValidationReport:
    """Everything that did not line up, counted. An empty report is the claim."""
    markers_found: int = 0
    variants_declared: int = 0
    missing_markers: list[str] = field(default_factory=list)
    orphan_markers: list[str] = field(default_factory=list)
    unbalanced_markers: list[str] = field(default_factory=list)
    unknown_guards: list[str] = field(default_factory=list)
    unknown_bypasses: list[str] = field(default_factory=list)
    safe_without_reason: list[str] = field(default_factory=list)
    declared_bypass_on_safe: list[str] = field(default_factory=list)

    @property
    def problems(self) -> list[str]:
        out = []
        for name in ("missing_markers", "orphan_markers", "unbalanced_markers",
                     "unknown_guards", "unknown_bypasses", "safe_without_reason",
                     "declared_bypass_on_safe"):
            values = getattr(self, name)
            if values:
                out.append(f"{name}: {', '.join(sorted(values))}")
        return out

    def render(self) -> str:
        head = (f"corpus: {self.variants_declared} variants declared, "
                f"{self.markers_found} source markers found")
        if not self.problems:
            return head + "\n  no mismatches"
        return head + "\n  " + "\n  ".join(self.problems)


def _scan_markers(path: Path) -> tuple[dict[str, tuple[int, int]], list[str]]:
    """Return {variant_id: (start, end)} plus the ids whose markers do not pair."""
    open_at: dict[str, int] = {}
    spans: dict[str, tuple[int, int]] = {}
    unbalanced: list[str] = []
    for number, line in enumerate(path.read_text().splitlines(), start=1):
        begin = BEGIN_RE.match(line)
        if begin:
            if begin.group(1) in open_at:
                unbalanced.append(f"{begin.group(1)} (begin twice)")
            open_at[begin.group(1)] = number
            continue
        end = END_RE.match(line)
        if end:
            start = open_at.pop(end.group(1), None)
            if start is None:
                unbalanced.append(f"{end.group(1)} (end without begin)")
            else:
                spans[end.group(1)] = (start, number)
    unbalanced += [f"{name} (begin without end)" for name in open_at]
    return spans, unbalanced


class Corpus:
    def __init__(self, path: Path | str = GROUND_TRUTH):
        self.path = Path(path)
        raw = yaml.safe_load(self.path.read_text())
        self.meta: dict = raw.get("meta", {})
        self.apps: dict[str, App] = {}
        for name, spec in raw.get("apps", {}).items():
            self.apps[name] = App(name=name, lang=spec["lang"], file=spec["file"],
                                  start=spec["start"], ready_marker=spec["ready_marker"],
                                  ready_match=spec.get("ready_match", "prefix"),
                                  min_runtime=spec.get("min_runtime", ""),
                                  framework=spec.get("framework", ""))
        self.variants: list[Variant] = []
        self._spans: dict[str, dict[str, tuple[int, int]]] = {}
        self._unbalanced: dict[str, list[str]] = {}
        for item in raw.get("variants", []):
            app = self.apps[item["app"]]
            self.variants.append(Variant(
                id=item["id"], app=app.name, lang=app.lang, file=app.file,
                sink=item.get("sink", ""), guards=list(item.get("guards", [])),
                flow=item.get("flow", ""), observability=item.get("observability", ""),
                label=item["label"], entry=item.get("entry", {}),
                bypasses_declared=list(item.get("bypasses_declared", [])),
                why_safe=(item.get("why_safe") or "").strip(),
                notes=(item.get("notes") or "").strip(),
                no_sink=bool(item.get("no_sink")), no_user_input=bool(item.get("no_user_input")),
                uses_shared=list(item.get("uses_shared", [])),
            ))
        self._attach_spans()

    def _attach_spans(self) -> None:
        for app in self.apps.values():
            source = REPO_ROOT / app.file
            if not source.exists():
                self._spans[app.name] = {}
                self._unbalanced[app.name] = [f"source file missing: {app.file}"]
                continue
            spans, unbalanced = _scan_markers(source)
            self._spans[app.name] = spans
            self._unbalanced[app.name] = unbalanced
        for variant in self.variants:
            spans = self._spans.get(variant.app, {})
            span = spans.get(variant.id)
            if span:
                variant.line_start, variant.line_end = span
            for name in variant.uses_shared:
                shared = spans.get(name)
                if shared:
                    variant.shared_spans[name] = shared

    def by_id(self, variant_id: str) -> Variant:
        for variant in self.variants:
            if variant.id == variant_id:
                return variant
        raise KeyError(variant_id)

    def for_app(self, app: str) -> list[Variant]:
        return [v for v in self.variants if v.app == app]

    def attribute_all(self, path: str, line: int) -> list[Variant]:
        """Every variant a finding at this location belongs to.

        A finding inside a shared helper belongs to each variant that routes
        through it, so this returns a list; ``attribute`` keeps the single-owner
        case for callers that only need one.
        """
        direct = [v for v in self.variants if v.covers_directly(path, line)]
        if direct:
            return direct
        return [v for v in self.variants if v.covers(path, line)]

    def attribute(self, path: str, line: int) -> Variant | None:
        """Map a static-analysis location to a variant, or None if it falls outside
        every labelled region. Callers must count the None results: an
        unattributed finding is neither a true nor a false positive until someone
        looks at it."""
        for variant in self.variants:
            if variant.covers(path, line):
                return variant
        return None

    def validate(self, known_bypasses: set[str] | None = None) -> ValidationReport:
        report = ValidationReport(
            markers_found=sum(len(s) for s in self._spans.values()),
            variants_declared=len(self.variants),
        )
        declared_guards = set(self.meta.get("guards", {}))
        declared_ids = {v.id for v in self.variants}

        for app, problems in self._unbalanced.items():
            report.unbalanced_markers += [f"{app}:{p}" for p in problems]
        used_shared = {name for v in self.variants for name in v.uses_shared}
        for app, spans in self._spans.items():
            for marker_id in spans:
                if marker_id.startswith("shared."):
                    if marker_id not in used_shared:
                        report.orphan_markers.append(f"{app}:{marker_id} (shared, unused)")
                elif marker_id not in declared_ids:
                    report.orphan_markers.append(f"{app}:{marker_id}")

        for variant in self.variants:
            if not variant.line_start:
                report.missing_markers.append(variant.id)
            report.unknown_guards += [f"{variant.id}:{g}" for g in variant.guards
                                      if g not in declared_guards]
            if known_bypasses is not None:
                report.unknown_bypasses += [f"{variant.id}:{b}" for b in variant.bypasses_declared
                                            if b not in known_bypasses]
            if variant.label == "safe" and not variant.why_safe:
                report.safe_without_reason.append(variant.id)
            if variant.label == "safe" and variant.bypasses_declared:
                report.declared_bypass_on_safe.append(variant.id)
            for name in variant.uses_shared:
                if name not in variant.shared_spans:
                    report.missing_markers.append(f"{variant.id}:{name}")
        return report

    def counts(self) -> dict[str, int]:
        return {
            "variants": len(self.variants),
            "vulnerable": sum(1 for v in self.variants if v.label == "vulnerable"),
            "safe": sum(1 for v in self.variants if v.label == "safe"),
            "apps": len(self.apps),
            "with_line_span": sum(1 for v in self.variants if v.line_start),
        }
