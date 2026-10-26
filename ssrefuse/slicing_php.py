"""Slicer for PHP sources.

The judge is shown a slice of a location rather than a whole file, and the
slice has to be the same *kind* of thing in every language or the comparison
between languages measures the slicer. So the driver at the bottom mirrors
``slicing_js.slice_javascript`` deliberately: imports first, then the
top-level statement the line sits in, then the functions it calls up to
``depth`` hops, then the module-level values that code refers to -- because a
guard cannot be judged without the allowlist it compares against.

Reusing the JavaScript scanner was tried first and rejected on a measurement,
not on taste. It runs on PHP and it does not find the enclosing function: it
returns a fixed window and notes that the sink is not inside a top-level
statement, which is a degraded slice that still looks like a slice. Worse, its
``classify`` understands regex literals, and ``_REGEX_PRECEDERS`` contains
``=``, so ordinary PHP division -- ``$a = $b / $c;`` -- would open a regex that
never closes and swallow the rest of the file. PHP has no regex literal, so
this scanner has none either.

What it does know, and what it refuses:

* line comments in both spellings, ``//`` and ``#``, with ``#[`` treated as a
  PHP 8 attribute rather than a comment, which is what it is.
* ``/* */``, with ``/** */`` counted separately so a docblock is reported the
  way the Python lab's docstrings are.
* single quotes, double quotes and backticks. Interpolation inside a
  double-quoted string is not parsed: the whole literal is masked, which is
  all a brace counter and an identifier scan need.
* heredoc and nowdoc (``<<<ID``) raise ``UnsupportedPhp``. They are not hard
  to add, but a scanner that half-understands them mis-ranks every brace after
  the first one, and a wrong slice is worse than a refused one.
* inline HTML outside ``<?php`` raises for the same reason, unless it is only
  whitespace.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ssrefuse.slicing import CodeSlice

CODE = 0
LINE_COMMENT = 1
BLOCK_COMMENT = 2
STRING = 3
INLINE_HTML = 4


class UnsupportedPhp(ValueError):
    """A construct this scanner will not guess at.

    A ``ValueError`` on purpose, so it surfaces the same way
    ``slice_source``'s "no slicer for this suffix" does: as a refusal at the
    call site rather than as a slice nobody can trust.
    """


def classify(source: str, fragment: bool = False) -> list[int]:
    """Per-character kind, so a brace in a string is not a brace.

    ``fragment=True`` starts the scan already inside PHP. A function body cut
    out of a file does not carry the opening tag, and scanning it as a whole
    file makes its first statement look like inline HTML -- which is how this
    scanner spent its first run raising on thirteen of sixteen variants.
    """
    kinds = [INLINE_HTML] * len(source)
    index = 0
    length = len(source)
    in_php = fragment

    while index < length:
        char = source[index]

        if not in_php:
            if source.startswith("<?php", index) or source.startswith("<?=", index):
                width = 5 if source.startswith("<?php", index) else 3
                for offset in range(width):
                    kinds[index + offset] = CODE
                index += width
                in_php = True
                continue
            if not char.isspace():
                line = source.count("\n", 0, index) + 1
                raise UnsupportedPhp(
                    f"inline HTML outside <?php at line {line}. This scanner "
                    f"only reads files that are PHP from the opening tag "
                    f"onwards; a template would need the output sections "
                    f"modelled, and guessing at them mis-ranks every brace "
                    f"after the first.")
            kinds[index] = INLINE_HTML
            index += 1
            continue

        if source.startswith("?>", index):
            kinds[index] = kinds[index + 1] = CODE
            index += 2
            in_php = False
            continue

        if source.startswith("<<<", index):
            line = source.count("\n", 0, index) + 1
            raise UnsupportedPhp(
                f"heredoc or nowdoc at line {line}. Not supported: the body "
                f"runs to a terminator this scanner does not track, so every "
                f"brace and quote after it would be misread. Rewrite the "
                f"literal, or teach the scanner the form.")

        if source.startswith("//", index):
            while index < length and source[index] != "\n":
                kinds[index] = LINE_COMMENT
                index += 1
            continue

        # `#[` opens an attribute, which is code. A bare `#` is a comment --
        # PHP's third comment spelling, and the one the JavaScript scanner
        # cannot see.
        if char == "#" and not source.startswith("#[", index):
            while index < length and source[index] != "\n":
                kinds[index] = LINE_COMMENT
                index += 1
            continue

        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            end = length if end == -1 else end + 2
            for offset in range(index, end):
                kinds[offset] = BLOCK_COMMENT
            index = end
            continue

        if char in "'\"`":
            quote = char
            kinds[index] = STRING
            index += 1
            while index < length:
                if source[index] == "\\" and index + 1 < length:
                    kinds[index] = STRING
                    kinds[index + 1] = STRING
                    index += 2
                    continue
                kinds[index] = STRING
                if source[index] == quote:
                    index += 1
                    break
                index += 1
            continue

        kinds[index] = CODE
        index += 1

    return kinds


def strip_annotations(source: str) -> tuple[list[str], dict[str, int]]:
    """Blank every comment, keeping line numbers intact.

    The lab is documented and the documentation names the vulnerability, so
    feeding it to a model would measure how well the model reads our prose.
    Removed characters become spaces and a line left with nothing becomes
    empty, so a finding at line N still points at line N on disk.
    """
    kinds = classify(source)
    chars = list(source)

    docblock_lines: set[int] = set()
    line_of = _line_index(source)
    for match in re.finditer(r"/\*\*", source):
        if kinds[match.start()] != BLOCK_COMMENT:
            continue
        index = match.start()
        while index < len(source) and kinds[index] == BLOCK_COMMENT:
            docblock_lines.add(line_of[index])
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
            if number - 1 in docblock_lines:
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


def _skeleton(source: str, fragment: bool = False) -> str:
    """Source with comments and string *contents* blanked.

    A brace inside a string literal is not a brace and a word inside a string
    is not a reference. ``preg_match('#^https?://host#i', $url)`` is the case
    that makes this non-optional here: the pattern contains ``#``, ``//`` and
    braces-adjacent punctuation, and all of it has to stay inert.

    Pass ``fragment=True`` for anything smaller than a whole file.
    """
    kinds = classify(source, fragment=fragment)
    return "".join(char if char == "\n" or kinds[index] == CODE else " "
                   for index, char in enumerate(source))


@dataclass
class TopLevel:
    kind: str
    name: str
    start: int
    end: int
    text: str


_FUNCTION_RE = re.compile(
    r"^\s*(?:(?:final|abstract|static|public|private|protected)\s+)*"
    r"function\s+&?([A-Za-z_]\w*)\s*\(")
_CONST_RE = re.compile(r"^\s*const\s+([A-Za-z_]\w*)\s*=")
_DEFINE_RE = re.compile(r"^\s*define\s*\(\s*['\"]([A-Za-z_]\w*)['\"]")
_GLOBAL_VAR_RE = re.compile(r"^\s*(\$[A-Za-z_]\w*)\s*=")
_IMPORT_RE = re.compile(r"^\s*(?:use\s|require\b|require_once\b|include\b|include_once\b|"
                        r"declare\s*\(|namespace\s)")


def top_level_statements(source: str) -> list[TopLevel]:
    """Functions, module values and imports, with their line spans.

    Spans are found by counting braces on the skeleton, so a ``{`` inside a
    string or a comment does not close a function early. A function's span
    starts at its signature and not at the docblock above it: the docblock is
    blanked anyway when ``strip`` is on, and including it would make an
    unstripped slice start with the answer.
    """
    skeleton = _skeleton(source)
    lines = source.splitlines()
    skeleton_lines = skeleton.splitlines()
    out: list[TopLevel] = []
    number = 0

    while number < len(lines):
        raw = lines[number]
        bare = skeleton_lines[number] if number < len(skeleton_lines) else ""
        match = _FUNCTION_RE.match(bare)
        if match:
            end = _matching_brace(skeleton_lines, number)
            out.append(TopLevel("function", match.group(1), number + 1, end + 1,
                                "\n".join(lines[number:end + 1])))
            number = end + 1
            continue
        if _IMPORT_RE.match(bare):
            out.append(TopLevel("import", "", number + 1, number + 1, raw))
            number += 1
            continue
        value = _CONST_RE.match(bare) or _DEFINE_RE.match(bare) or _GLOBAL_VAR_RE.match(bare)
        if value:
            end = _statement_end(skeleton_lines, number)
            out.append(TopLevel("value", value.group(1), number + 1, end + 1,
                                "\n".join(lines[number:end + 1])))
            number = end + 1
            continue
        number += 1
    return out


def _matching_brace(skeleton_lines: list[str], start: int) -> int:
    """Last line of the block opened on or after ``start``."""
    depth = 0
    seen = False
    for number in range(start, len(skeleton_lines)):
        for char in skeleton_lines[number]:
            if char == "{":
                depth += 1
                seen = True
            elif char == "}":
                depth -= 1
                if seen and depth == 0:
                    return number
    return len(skeleton_lines) - 1


def _statement_end(skeleton_lines: list[str], start: int) -> int:
    """Last line of a statement, following brackets so an array literal holds."""
    depth = 0
    for number in range(start, len(skeleton_lines)):
        for char in skeleton_lines[number]:
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
            elif char == ";" and depth <= 0:
                return number
    return start


_CALL_RE = re.compile(r"([A-Za-z_]\w*)\s*\(")
_NAME_RE = re.compile(r"\$?[A-Za-z_]\w*")
# Language forms that look like calls. `print` and `echo` are statements,
# `array` and `list` are constructs, and the rest are control flow.
_DECLARED = {"if", "elseif", "else", "for", "foreach", "while", "switch", "match",
             "catch", "return", "function", "fn", "echo", "print", "array", "list",
             "isset", "unset", "empty", "require", "require_once", "include",
             "include_once", "declare", "exit", "die", "new", "clone", "throw",
             "and", "or", "xor", "instanceof", "int", "string", "bool", "float"}


def slice_php(path: str | Path, line: int, depth: int = 2, strip: bool = True,
              include_functions: list[str] | None = None,
              include_values: list[str] | None = None) -> CodeSlice:
    """Slice a PHP file around ``line``. See the module docstring."""
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

    label = (f"sink is in {focus.name}()" if focus.kind == "function"
             else f"sink is in the {focus.name} definition" if focus.name
             else "sink is in a top-level statement")
    result.regions.append((focus.start, focus.end, label))

    included = {focus.name} if focus.name else set()
    frontier = [focus]
    for hop in range(depth):
        next_frontier = []
        for statement in frontier:
            for name in _CALL_RE.findall(_skeleton(statement.text, fragment=True)):
                if name in functions and name not in included:
                    included.add(name)
                    target = functions[name]
                    result.regions.append(
                        (target.start, target.end,
                         f"called from {statement.name or 'the handler'}, hop {hop + 1}"))
                    next_frontier.append(target)
                elif name not in functions and name not in _DECLARED:
                    # A built-in or a function from another file. Named rather
                    # than dropped: `file_get_contents` and `curl_exec` are the
                    # sinks, and a slice that silently omitted the fact that
                    # the call leaves this file would read as complete.
                    result.unresolved_calls.append(name)
        frontier = next_frontier
        if not frontier:
            break

    referenced: set[str] = set()
    for statement in [focus] + [functions[name] for name in included if name in functions]:
        referenced |= set(_NAME_RE.findall(_skeleton(statement.text, fragment=True)))
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
                                f"file-level function in this file")
    for name in include_values or []:
        target = values.get(name) or values.get(f"${name.lstrip('$')}")
        if target is not None:
            result.regions.append((target.start, target.end,
                                   f"requested by the judge: {name}"))
        else:
            result.notes.append(f"judge asked for value {name!r}, which this file "
                                f"does not define at file level")

    result.unresolved_calls = sorted(set(result.unresolved_calls) - _DECLARED)
    if result.unresolved_calls:
        result.notes.append("calls into PHP built-ins or other files were not "
                            "expanded: " + ", ".join(result.unresolved_calls[:12]))
    return result
