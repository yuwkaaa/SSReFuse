"""Code slicing for JavaScript.

The Python slicer walks an AST. There is no JavaScript parser in this project's
dependency set and adding one costs an npm tree, so this slicer works from a
character scan instead: one pass classifies every character as code, comment,
string or template, and both consumers -- the comment stripper and the
brace counter that finds statement boundaries -- read that one classification.

A scanner is weaker than a parser and the weakness has to be visible rather
than assumed away, so:

* the scan is tested against a fixture whose expected output is written down
  (``tests/test_slicing_js.py``), because a wrong total looks exactly like a
  right one;
* the only genuinely ambiguous construct in JavaScript lexing, telling a regex
  literal apart from division, is resolved by the usual previous-token rule and
  that rule is stated here rather than buried: a ``/`` begins a regex when the
  last significant character is one of ``( , = : [ ! & | ? { } ; + - * % ^ ~ <
  > ~`` or the last word is a keyword that cannot end an expression;
* anything the slicer could not resolve is recorded in ``unresolved_calls`` and
  ``notes`` and travels into the prompt, so a judgement made on an incomplete
  slice is never silently presented as a judgement made on a complete one.
"""
from __future__ import annotations

import re
from pathlib import Path

from ssrefuse.slicing import CodeSlice

# Characters after which a '/' opens a regular expression rather than dividing.
_REGEX_PRECEDERS = set("(,=:[!&|?{};+-*%^~<>")
# Words after which the same is true. A '/' after an identifier, a number or a
# closing bracket is division.
_REGEX_KEYWORDS = {"return", "typeof", "instanceof", "in", "of", "new", "delete",
                   "void", "throw", "case", "do", "else", "yield", "await"}

CODE, LINE_COMMENT, BLOCK_COMMENT, STRING, TEMPLATE, REGEX = range(6)


def classify(source: str) -> list[int]:
    """Classify every character of ``source``.

    Template substitutions are classified as code, because the identifiers
    inside ``${...}`` are real references and a slice that dropped them would
    omit the constant a guard compares against.
    """
    kinds = [CODE] * len(source)
    index = 0
    length = len(source)
    last_significant = ""
    template_depth: list[int] = []   # brace depth inside the current ${ ... }

    while index < length:
        char = source[index]
        two = source[index:index + 2]

        if two == "//":
            while index < length and source[index] != "\n":
                kinds[index] = LINE_COMMENT
                index += 1
            continue
        if two == "/*":
            while index < length and source[index:index + 2] != "*/":
                kinds[index] = BLOCK_COMMENT
                index += 1
            for _ in range(min(2, length - index)):
                kinds[index] = BLOCK_COMMENT
                index += 1
            continue
        if char in "\"'":
            quote = char
            kinds[index] = STRING
            index += 1
            while index < length:
                kinds[index] = STRING
                if source[index] == "\\":
                    if index + 1 < length:
                        kinds[index + 1] = STRING
                    index += 2
                    continue
                if source[index] == quote or source[index] == "\n":
                    index += 1
                    break
                index += 1
            last_significant = quote
            continue
        if char == "`":
            kinds[index] = TEMPLATE
            index += 1
            while index < length:
                if source[index] == "\\":
                    kinds[index] = TEMPLATE
                    if index + 1 < length:
                        kinds[index + 1] = TEMPLATE
                    index += 2
                    continue
                if source[index:index + 2] == "${":
                    kinds[index] = kinds[index + 1] = TEMPLATE
                    index += 2
                    depth = 1
                    # The substitution is code: classify it as such, tracking
                    # braces so a nested object literal does not end it early.
                    while index < length and depth:
                        if source[index] == "{":
                            depth += 1
                        elif source[index] == "}":
                            depth -= 1
                            if depth == 0:
                                kinds[index] = TEMPLATE
                                index += 1
                                break
                        kinds[index] = CODE
                        index += 1
                    continue
                kinds[index] = TEMPLATE
                if source[index] == "`":
                    index += 1
                    break
                index += 1
            last_significant = "`"
            continue
        if char == "/" and (last_significant in _REGEX_PRECEDERS or last_significant == ""):
            index = _scan_regex(source, index, kinds)
            last_significant = "/"
            continue
        if char == "/":
            word = re.search(r"([A-Za-z_$][\w$]*)\s*$", source[:index])
            if word and word.group(1) in _REGEX_KEYWORDS:
                index = _scan_regex(source, index, kinds)
                last_significant = "/"
                continue

        if not char.isspace():
            last_significant = char
        index += 1

    template_depth.clear()
    return kinds


def _scan_regex(source: str, index: int, kinds: list[int]) -> int:
    """Consume a regex literal starting at ``index``; return the index after it."""
    length = len(source)
    kinds[index] = REGEX
    index += 1
    in_class = False
    while index < length:
        kinds[index] = REGEX
        char = source[index]
        if char == "\\":
            if index + 1 < length:
                kinds[index + 1] = REGEX
            index += 2
            continue
        if char == "\n":
            index += 1
            break
        if char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        elif char == "/" and not in_class:
            index += 1
            while index < length and source[index].isalpha():   # flags
                kinds[index] = REGEX
                index += 1
            break
        index += 1
    return index


def strip_annotations(source: str) -> tuple[list[str], dict[str, int]]:
    """Blank every comment, keeping line numbers intact.

    The lab sources are documented and the documentation names the
    vulnerability, so feeding it to a model measures how well the model reads
    our prose. Removed characters become spaces and a line left with nothing
    becomes empty, so a finding at line N still points at line N on disk.
    JSDoc blocks are counted separately because they are what the Python lab
    calls a docstring.
    """
    kinds = classify(source)
    chars = list(source)
    jsdoc_spans: set[int] = set()
    for match in re.finditer(r"/\*\*", source):
        if kinds[match.start()] == BLOCK_COMMENT:
            jsdoc_spans.add(match.start())

    jsdoc_lines: set[int] = set()
    if jsdoc_spans:
        line_of = _line_index(source)
        for start in jsdoc_spans:
            index = start
            while index < len(source) and kinds[index] == BLOCK_COMMENT:
                jsdoc_lines.add(line_of[index])
                index += 1

    for index, kind in enumerate(kinds):
        if kind in (LINE_COMMENT, BLOCK_COMMENT) and chars[index] != "\n":
            chars[index] = " "

    original = source.splitlines()
    lines = "".join(chars).splitlines()
    removed = {"comment_lines": 0, "docstring_lines": 0, "inline_comments": 0}
    for number, (before, after) in enumerate(zip(original, lines), start=1):
        if before == after:
            continue
        if not after.strip():
            if number - 1 in jsdoc_lines:
                removed["docstring_lines"] += 1
            else:
                removed["comment_lines"] += 1
            lines[number - 1] = ""
        else:
            removed["inline_comments"] += 1
            lines[number - 1] = after.rstrip()
    return lines, removed


def _line_index(source: str) -> list[int]:
    """Map character offset -> zero-based line number."""
    out: list[int] = []
    line = 0
    for char in source:
        out.append(line)
        if char == "\n":
            line += 1
    out.append(line)
    return out


def _skeleton(source: str) -> str:
    """Source with comments and string *contents* blanked.

    Used for counting brackets and for finding identifiers: a brace inside a
    string literal or a character class is not a brace, and a word inside a
    string is not a reference.
    """
    kinds = classify(source)
    chars = []
    for index, char in enumerate(source):
        if char == "\n":
            chars.append(char)
        elif kinds[index] == CODE:
            chars.append(char)
        else:
            chars.append(" ")
    return "".join(chars)


class TopLevel:
    __slots__ = ("start", "end", "kind", "name", "text")

    def __init__(self, start: int, end: int, kind: str, name: str, text: str):
        self.start, self.end, self.kind, self.name, self.text = start, end, kind, name, text

    def __repr__(self) -> str:   # pragma: no cover - debugging aid
        return f"TopLevel({self.kind}:{self.name} {self.start}-{self.end})"


_FUNCTION_RE = re.compile(r"^\s*(?:async\s+)?function\s+([A-Za-z_$][\w$]*)")
_ARROW_RE = re.compile(r"^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
                       r"(?:async\s*)?(?:\(|function\b)")
_VALUE_RE = re.compile(r"^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=")
_ROUTE_RE = re.compile(r"^\s*\w+\.(get|post|put|patch|delete|head|options|use)\s*\(")
_IMPORT_RE = re.compile(r"^\s*(?:import\b|(?:const|let|var)\s+.*=\s*require\s*\()")


def top_level_statements(source: str) -> list[TopLevel]:
    """Split a module into its top-level statements by counting brackets.

    A statement runs from the first line with code while the bracket depth is
    zero to the line where the depth returns to zero. That is exactly how the
    region a sink belongs to is found: no parser, but no heuristics about
    indentation either.
    """
    skeleton_lines = _skeleton(source).splitlines()
    raw_lines = source.splitlines()
    statements: list[TopLevel] = []
    depth = 0
    start: int | None = None
    for number, line in enumerate(skeleton_lines, start=1):
        has_code = bool(line.strip())
        if start is None and has_code:
            start = number
        depth += line.count("{") + line.count("(") + line.count("[")
        depth -= line.count("}") + line.count(")") + line.count("]")
        if start is not None and has_code and depth <= 0:
            text = "\n".join(raw_lines[start - 1:number])
            statements.append(TopLevel(start, number, *_classify_statement(text), text))
            start = None
            depth = 0
    if start is not None:
        text = "\n".join(raw_lines[start - 1:])
        statements.append(TopLevel(start, len(raw_lines), *_classify_statement(text), text))
    return statements


def _classify_statement(text: str) -> tuple[str, str]:
    first = text.splitlines()[0] if text.splitlines() else ""
    if _IMPORT_RE.match(first):
        return "import", ""
    match = _FUNCTION_RE.match(first)
    if match:
        return "function", match.group(1)
    match = _ARROW_RE.match(first)
    if match:
        return "function", match.group(1)
    match = _VALUE_RE.match(first)
    if match:
        return "value", match.group(1)
    match = _ROUTE_RE.match(first)
    if match:
        path = re.search(r"""['"]([^'"]+)['"]""", first)
        return "route", path.group(1) if path else ""
    return "other", ""


_CALL_RE = re.compile(r"([A-Za-z_$][\w$.]*)\s*\(")
_NAME_RE = re.compile(r"[A-Za-z_$][\w$]*")
_DECLARED = {"if", "for", "while", "switch", "catch", "return", "function", "typeof",
             "await", "new", "else", "do", "try"}


def slice_javascript(path: str | Path, line: int, depth: int = 2,
                     strip: bool = True, include_functions: list[str] | None = None,
                     include_values: list[str] | None = None) -> CodeSlice:
    """Slice a JavaScript file around ``line``.

    Includes the requires and imports, the top-level statement the line sits in
    (a route registration or a function declaration), the module-level
    functions it calls transitively up to ``depth`` hops, and the module-level
    values any included code refers to -- the allowlists and denylists live
    there, and a guard cannot be judged without the values it compares against.
    """
    path = Path(path)
    source = path.read_text()
    statements = top_level_statements(source)
    if strip:
        rendered, removed = strip_annotations(source)
    else:
        rendered, removed = source.splitlines(), {}
    result = CodeSlice(file=str(path), focus_line=line, source_lines=rendered,
                       stripped=strip, removed=removed)

    functions = {s.name: s for s in statements if s.kind == "function" and s.name}
    values = {s.name: s for s in statements if s.kind == "value" and s.name}
    imports = [s for s in statements if s.kind == "import"]
    if imports:
        result.regions.append((min(s.start for s in imports), max(s.end for s in imports),
                               "imports: which libraries the sinks come from"))

    focus = next((s for s in statements if s.start <= line <= s.end), None)
    if focus is None:
        start = max(1, line - 12)
        end = min(len(result.source_lines), line + 12)
        result.regions.append((start, end, "no enclosing statement; fixed window"))
        result.notes.append("the sink is not inside a top-level statement")
        return result

    label = (f"sink is in the {focus.name} route handler" if focus.kind == "route"
             else f"sink is in {focus.name}()" if focus.name
             else "sink is in a top-level statement")
    result.regions.append((focus.start, focus.end, label))

    included = {focus.name} if focus.name else set()
    frontier = [focus]
    for hop in range(depth):
        next_frontier = []
        for statement in frontier:
            for name in _CALL_RE.findall(_skeleton_of(statement.text)):
                root = name.split(".")[0]
                if root in functions and root not in included:
                    included.add(root)
                    target = functions[root]
                    result.regions.append(
                        (target.start, target.end,
                         f"called from {statement.name or 'the handler'}, hop {hop + 1}"))
                    next_frontier.append(target)
                elif root not in functions and "." in name:
                    result.unresolved_calls.append(name)
        frontier = next_frontier
        if not frontier:
            break

    referenced: set[str] = set()
    for statement in [focus] + [functions[name] for name in included if name in functions]:
        referenced |= set(_NAME_RE.findall(_skeleton_of(statement.text)))
    for name in sorted(referenced & set(values)):
        target = values[name]
        result.regions.append((target.start, target.end,
                               f"module value {name} used by the code above"))

    for name in include_functions or []:
        clean = name.split("(")[0].strip()
        target = functions.get(clean)
        if target is not None and clean not in included:
            result.regions.append((target.start, target.end,
                                   f"requested by the judge: {name}"))
            included.add(clean)
        elif target is None:
            result.notes.append(f"judge asked for {name!r}, which is not a "
                                f"module-level function in this file")
    for name in include_values or []:
        target = values.get(name)
        if target is not None:
            result.regions.append((target.start, target.end,
                                   f"requested by the judge: {name}"))
        else:
            result.notes.append(f"judge asked for value {name!r}, which this file "
                                f"does not define at module level")

    result.unresolved_calls = sorted(set(result.unresolved_calls) - _DECLARED)
    if result.unresolved_calls:
        result.notes.append("calls into other modules were not expanded: "
                            + ", ".join(result.unresolved_calls[:12]))
    return result


def _skeleton_of(text: str) -> str:
    return _skeleton(text)
