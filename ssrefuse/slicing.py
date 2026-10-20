"""Inter-procedural code slicing around a sink.

This is the part that decides how well the LLM pass works, and it is also the
reason the pipeline is fused rather than "ask a model about the repository". A
model handed a 450-line file has to find the sink before it can reason about it;
a model handed the sink, the function around it, the helpers that function calls
and the module constants those helpers compare against has nothing left to do
but the reasoning.

The slice records what it left out. A judgement made on a slice that silently
dropped the guard is worth nothing, so ``notes`` carries every call the slicer
could not resolve, and the prompt passes that list to the model.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path


def strip_annotations(source: str) -> tuple[list[str], dict[str, int]]:
    """Remove comments and docstrings, keeping every line number intact.

    The lab sources are documented, and the documentation says which route is
    vulnerable and why. Feeding that to a language model measures how well it
    reads our comments, not how well it reads code -- the failure that makes
    annotated vulnerability benchmarks flatter LLMs. Removed lines become empty
    strings rather than disappearing, so a finding at line N still points at
    line N of the file on disk.

    Returns the lines plus how much was removed, because a slice that quietly
    dropped most of its content should be visible in the report.
    """
    lines = source.splitlines()
    blanked = {"comment_lines": 0, "docstring_lines": 0, "inline_comments": 0}

    tree = ast.parse(source)
    doc_spans: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
            continue
        body = getattr(node, "body", [])
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            doc_spans.append((body[0].lineno, body[0].end_lineno or body[0].lineno))
    for start, end in doc_spans:
        for number in range(start, end + 1):
            if lines[number - 1].strip():
                blanked["docstring_lines"] += 1
            lines[number - 1] = ""

    # Comments are removed with the tokenizer rather than by searching for "#",
    # because a payload or an allowlist entry may contain that character.
    import io
    import tokenize

    comment_tokens = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT:
                comment_tokens.append(token)
    except (tokenize.TokenError, IndentationError):
        pass
    for token in comment_tokens:
        row = token.start[0]
        if row - 1 >= len(lines):
            continue
        before = lines[row - 1][:token.start[1]]
        if before.strip():
            lines[row - 1] = before.rstrip()
            blanked["inline_comments"] += 1
        else:
            lines[row - 1] = ""
            blanked["comment_lines"] += 1
    return lines, blanked


@dataclass
class CodeSlice:
    file: str
    focus_line: int
    regions: list[tuple[int, int, str]] = field(default_factory=list)  # start, end, why
    unresolved_calls: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    source_lines: list[str] = field(default_factory=list)
    stripped: bool = True
    removed: dict[str, int] = field(default_factory=dict)

    def render(self) -> str:
        """The slice as numbered source with explicit gaps."""
        out: list[str] = []
        if self.stripped:
            out.append("      # comments and docstrings removed before slicing")
        previous_end = 0
        for start, end, why in sorted(self.regions):
            if start > previous_end + 1:
                out.append(f"      ... {start - previous_end - 1} line(s) omitted ...")
            out.append(f"      # [{why}]")
            for number in range(start, end + 1):
                if 1 <= number <= len(self.source_lines):
                    marker = ">>" if number == self.focus_line else "  "
                    out.append(f"{marker}{number:5d}  {self.source_lines[number - 1]}")
            previous_end = max(previous_end, end)
        return "\n".join(out)

    def line_count(self) -> int:
        return sum(end - start + 1 for start, end, _ in self.regions)


def _enclosing_function(tree: ast.Module, line: int) -> ast.FunctionDef | None:
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = min([node.lineno] + [d.lineno for d in node.decorator_list])
            end = getattr(node, "end_lineno", node.lineno)
            if start <= line <= end:
                if best is None or start > best[0]:
                    best = (start, node)
    return best[1] if best else None


def _span(node: ast.AST) -> tuple[int, int]:
    start = getattr(node, "lineno", 0)
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.decorator_list:
        start = min(start, min(d.lineno for d in node.decorator_list))
    return start, getattr(node, "end_lineno", start)


def _called_names(node: ast.AST) -> list[str]:
    names = []
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func = child.func
            if isinstance(func, ast.Name):
                names.append(func.id)
            elif isinstance(func, ast.Attribute):
                names.append(ast.unparse(func))
    return names


def _referenced_names(node: ast.AST) -> set[str]:
    return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}


def slice_python(path: str | Path, line: int, depth: int = 2,
                 strip: bool = True, include_functions: list[str] | None = None,
                 include_values: list[str] | None = None) -> CodeSlice:
    """Slice a Python file around ``line``.

    Includes the imports, the enclosing function, module-level functions it calls
    transitively up to ``depth`` hops, and the module-level assignments whose
    names any included code refers to -- the allowlists and denylists live there,
    and a guard cannot be judged without the values it compares against.

    With ``strip`` left on, comments and docstrings are blanked first, so a
    judgement cannot come from reading the lab's own documentation.
    """
    path = Path(path)
    source = path.read_text()
    tree = ast.parse(source)
    if strip:
        rendered, removed = strip_annotations(source)
    else:
        rendered, removed = source.splitlines(), {}
    result = CodeSlice(file=str(path), focus_line=line, source_lines=rendered,
                       stripped=strip, removed=removed)

    module_functions: dict[str, ast.AST] = {}
    module_assignments: dict[str, ast.AST] = {}
    import_spans: list[tuple[int, int]] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            module_functions[node.name] = node
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            import_spans.append(_span(node))
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    module_assignments[target.id] = node

    if import_spans:
        result.regions.append((min(s for s, _ in import_spans),
                               max(e for _, e in import_spans),
                               "imports: which libraries the sinks come from"))

    focus = _enclosing_function(tree, line)
    if focus is None:
        start = max(1, line - 12)
        end = min(len(result.source_lines), line + 12)
        result.regions.append((start, end, "no enclosing function; fixed window"))
        result.notes.append("the sink is not inside a function definition")
        return result

    start, end = _span(focus)
    result.regions.append((start, end, f"sink is in {focus.name}()"))

    included = {focus.name}
    frontier = [focus]
    for hop in range(depth):
        next_frontier = []
        for node in frontier:
            for name in _called_names(node):
                root = name.split(".")[0]
                if root in module_functions and root not in included:
                    included.add(root)
                    target = module_functions[root]
                    tstart, tend = _span(target)
                    result.regions.append(
                        (tstart, tend, f"called from {getattr(node, 'name', '?')}(), hop {hop + 1}"))
                    next_frontier.append(target)
                elif root not in module_functions and "." in name:
                    result.unresolved_calls.append(name)
        frontier = next_frontier
        if not frontier:
            break

    referenced: set[str] = set()
    for node_name in included:
        referenced |= _referenced_names(module_functions[node_name])
    for name in sorted(referenced & set(module_assignments)):
        astart, aend = _span(module_assignments[name])
        result.regions.append((astart, aend, f"module value {name} used by the code above"))

    # Names a previous round asked for by hand. This is what lets the judge
    # widen its own view instead of guessing from an incomplete slice.
    for name in include_functions or []:
        target = module_functions.get(name.split("(")[0].strip())
        if target is not None and name not in included:
            tstart, tend = _span(target)
            result.regions.append((tstart, tend, f"requested by the judge: {name}"))
            included.add(name)
        elif target is None:
            result.notes.append(f"judge asked for {name!r}, which is not a "
                                f"module-level function in this file")
    for name in include_values or []:
        node = module_assignments.get(name)
        if node is not None:
            astart, aend = _span(node)
            result.regions.append((astart, aend, f"requested by the judge: {name}"))
        else:
            result.notes.append(f"judge asked for value {name!r}, which this file "
                                f"does not define at module level")

    result.unresolved_calls = sorted(set(result.unresolved_calls))
    if result.unresolved_calls:
        result.notes.append(
            "calls into other modules were not expanded: "
            + ", ".join(result.unresolved_calls[:12]))
    return result
