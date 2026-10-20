"""The JavaScript scanner and slicer, against results written down in advance.

The Python slicer is backed by a parser, so its correctness is the parser's.
This one is a character scanner, so it gets a control file whose expected
output is stated here. Every number below was decided by reading
`tests/fixtures/js_scanner_control.js`, not by printing what the scanner
produced: a scanner that mistakes a regex for a division, or a `//` inside a
string for a comment, returns a plausible wrong answer, and only a fixture
with a known answer tells the difference.
"""
import pytest

from ssrefuse.corpus import REPO_ROOT, Corpus
from ssrefuse.slicing_js import (BLOCK_COMMENT, CODE, LINE_COMMENT, STRING,
                                 classify, slice_javascript, strip_annotations,
                                 top_level_statements)

CONTROL = REPO_ROOT / "tests" / "fixtures" / "js_scanner_control.js"
SOURCE = CONTROL.read_text()
LAB = REPO_ROOT / "corpus/labs/node_ssrf/app.js"


def test_the_control_file_splits_into_the_statements_it_has():
    """Seven top-level statements, counted by hand from the fixture."""
    statements = top_level_statements(SOURCE)
    assert len(statements) == 7, [str(s) for s in statements]
    assert [s.kind for s in statements] == [
        "other", "value", "value", "value", "value", "function", "other"]
    assert [s.name for s in statements if s.name] == [
        "NOT_A_COMMENT", "TEMPLATE", "PATTERN", "RATIO", "controlFunction"]


def test_a_double_slash_inside_a_string_is_not_a_comment():
    index = SOURCE.index("//path")
    kinds = classify(SOURCE)
    assert kinds[index] == STRING
    assert kinds[index + 1] == STRING


def test_a_regex_literal_is_not_division_and_its_braces_do_not_count():
    kinds = classify(SOURCE)
    start = SOURCE.index("/[/{}()[\\]]+/g")
    assert kinds[start] != LINE_COMMENT
    # The braces inside the character class must not be seen as code, or the
    # statement that holds them never closes and everything after it merges
    # into one region.
    assert kinds[SOURCE.index("{}()", start)] not in (CODE,)


def test_division_is_not_mistaken_for_a_regex():
    kinds = classify(SOURCE)
    index = SOURCE.index("10 / 2 / 1") + 3
    assert SOURCE[index] == "/"
    assert kinds[index] == CODE


def test_template_substitutions_stay_code_so_their_references_survive():
    kinds = classify(SOURCE)
    index = SOURCE.index("${NOT_A_COMMENT}") + 2
    assert kinds[index] == CODE, "a constant referenced inside a template was blanked"


def test_stripping_counts_jsdoc_apart_from_line_comments():
    lines, removed = strip_annotations(SOURCE)
    assert len(lines) == len(SOURCE.splitlines())
    assert removed["docstring_lines"] == 5, removed
    assert removed["comment_lines"] == 6, removed
    assert "JSDoc block" not in "\n".join(lines)
    assert "//path?a={b}" in "\n".join(lines), "a string literal was stripped as a comment"


def test_every_lab_route_falls_inside_exactly_one_statement():
    """Attribution depends on this: a route the scanner merged into its
    neighbour would hand the judge the wrong code with no sign of it."""
    corpus = Corpus()
    statements = top_level_statements(LAB.read_text())
    for variant in corpus.for_app("node_ssrf"):
        covering = [s for s in statements
                    if s.start <= variant.line_start + 2 <= s.end]
        assert len(covering) == 1, f"{variant.id}: {len(covering)} statements cover it"


@pytest.mark.parametrize("variant_id,expected", [
    ("js-007", "BLOCKED_HOSTS"),
    ("js-009", "ALLOWED_ORIGIN"),
    ("js-023", "ALLOWED_ORIGIN"),
])
def test_the_guard_values_are_in_the_slice(variant_id, expected):
    variant = Corpus().by_id(variant_id)
    text = slice_javascript(REPO_ROOT / variant.file, variant.line_start + 4).render()
    assert expected in text, f"{variant_id}: the slice dropped {expected}"


def test_interprocedural_slice_reaches_the_shared_sink():
    variant = Corpus().by_id("js-003")
    text = slice_javascript(REPO_ROOT / variant.file, variant.line_start + 3).render()
    assert "fetchRemote" in text
    assert "await fetch(target" in text, "the slice omitted the sink itself"


def test_unresolved_calls_are_reported_rather_than_dropped():
    variant = Corpus().by_id("js-014")
    result = slice_javascript(REPO_ROOT / variant.file, variant.line_start + 4)
    assert any("dns.promises.lookup" in call for call in result.unresolved_calls)
    assert any("not expanded" in note for note in result.notes)


def test_asking_for_something_absent_is_recorded_not_ignored():
    variant = Corpus().by_id("js-001")
    result = slice_javascript(REPO_ROOT / variant.file, variant.line_start + 1,
                              include_functions=["noSuchFunction"])
    assert any("noSuchFunction" in note for note in result.notes)
