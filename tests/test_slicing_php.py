"""The PHP scanner, pinned on the two bugs it shipped with and the four it refuses.

Both bugs were found by a contradiction rather than by reading: the same file
raised for thirteen variants and fell back to a fixed window for three, which
cannot both be true of one file, so the measurement was wrong before the code
was. Keeping them as tests is cheaper than finding them twice.
"""
import pytest

from ssrefuse.slicing import slice_source
from ssrefuse.slicing_php import (
    CODE, LINE_COMMENT, STRING, UnsupportedPhp, classify, strip_annotations,
    top_level_statements,
)

LAB = "corpus/labs/php_ssrf/app.php"


# --- the two bugs ----------------------------------------------------------

def test_a_fragment_is_scanned_as_php_not_as_a_new_file():
    """Bug one. A function body cut out of a file carries no `<?php`, so
    scanning it as a whole file made its first statement look like inline HTML
    and raised on it."""
    fragment = "$url = $_GET['url'];\nreturn file_get_contents($url);\n"
    with pytest.raises(UnsupportedPhp):
        classify(fragment)                       # as a file: refused, correctly
    kinds = classify(fragment, fragment=True)    # as a fragment: ordinary code
    assert kinds[0] == CODE


def test_the_lab_slices_with_its_enclosing_function_found():
    """Bug two was in the measurement, not the scanner: the sink line was
    located by searching the raw source, and the docblock names the sink in
    prose, so the focus line landed inside a comment and no function contained
    it. Search the stripped source."""
    stripped, _ = strip_annotations(open(LAB).read())
    sink_line = next(n for n, text in enumerate(stripped, 1)
                     if "file_get_contents(" in text)
    result = slice_source(LAB, sink_line, depth=2, strip=True)
    assert any("sink is in" in why for _, _, why in result.regions), result.notes
    assert "no enclosing statement; fixed window" not in [w for _, _, w in result.regions]


# --- what it refuses rather than guesses at --------------------------------

def test_a_heredoc_is_refused_rather_than_mis_scanned():
    """A body running to a terminator the scanner does not track would misread
    every brace after it. A refused slice beats a wrong one."""
    with pytest.raises(UnsupportedPhp, match="heredoc"):
        classify("<?php\n$x = <<<SQL\n  anything {\nSQL;\n")


def test_inline_html_is_refused():
    with pytest.raises(UnsupportedPhp, match="inline HTML"):
        classify("<h1>hello</h1>\n<?php $x = 1;\n")


def test_leading_whitespace_before_the_tag_is_fine():
    """The control for the test above, or it would only prove that something
    raises."""
    assert classify("\n  \n<?php $x = 1;\n")[-6] == CODE


# --- the lexical forms PHP has and JavaScript does not ---------------------

def test_a_hash_is_a_comment_and_hash_bracket_is_an_attribute():
    """PHP's third comment spelling, and the PHP 8 form that looks like it.
    Reading `#[Attribute]` as a comment would blank a line of real code."""
    source = "<?php\n# a hash comment\n#[Deprecated]\nfunction f(): void {}\n"
    kinds = classify(source)
    hash_comment = source.index("# a hash")
    attribute = source.index("#[Deprecated]")
    assert kinds[hash_comment] == LINE_COMMENT
    assert kinds[attribute] == CODE


def test_division_is_not_a_regex_literal():
    """The reason this scanner exists instead of the JavaScript one. There,
    `=` can precede a regex, so `$b / $c` opens a literal that never closes and
    swallows the rest of the file -- every brace after it misread."""
    source = "<?php\n$a = $b / $c;\nfunction after(): void { $x = 1; }\n"
    kinds = classify(source)
    assert kinds[source.index("function after")] == CODE
    assert [s.name for s in top_level_statements(source) if s.kind == "function"] == ["after"]


def test_a_pattern_containing_comment_and_path_characters_stays_inert():
    """`preg_match('#^https?://host#i', ...)` is in the lab: a `#`, a `//` and
    a `?` inside a single-quoted string, none of which may start anything."""
    source = ("<?php\nfunction guard(): bool {\n"
              "    return preg_match('#^https?://host#i', $u) === 1;\n}\n")
    kinds = classify(source)
    assert kinds[source.index("#^https")] == STRING
    assert [s.name for s in top_level_statements(source) if s.kind == "function"] == ["guard"]


# --- stripping -------------------------------------------------------------

def test_stripping_keeps_line_numbers_and_counts_docblocks_apart():
    """A finding at line N has to still point at line N, and a docblock is what
    this lab calls a docstring, so it is counted separately."""
    source = open(LAB).read()
    lines, removed = strip_annotations(source)
    assert len(lines) == len(source.splitlines())
    assert removed["docstring_lines"] > 40, removed
    assert not any("SSReFuse lab application" in line for line in lines)


def test_the_answer_is_not_left_in_a_stripped_slice():
    """The lab's prose says which guard is broken. A slice that kept it would
    measure how well the model reads our writing."""
    stripped, _ = strip_annotations(open(LAB).read())
    sink_line = next(n for n, text in enumerate(stripped, 1)
                     if "file_get_contents(" in text)
    rendered = slice_source(LAB, sink_line, depth=2, strip=True).render()
    for giveaway in ("does not canonicalise", "walks straight through",
                     "measured on 8.4.27", "vulnerable"):
        assert giveaway not in rendered, giveaway


# --- what the slice is made of --------------------------------------------

def test_the_slice_carries_the_values_a_guard_is_judged_against():
    """A hostname allowlist cannot be judged without the allowlist."""
    stripped, _ = strip_annotations(open(LAB).read())
    sink_line = next(n for n, text in enumerate(stripped, 1)
                     if "ALLOWED_HOST" in text and "!==" in text)
    result = slice_source(LAB, sink_line, depth=2, strip=True)
    assert any("module value ALLOWED_HOST" in why for _, _, why in result.regions), \
        [w for _, _, w in result.regions]


def test_builtin_sinks_are_named_as_unexpanded_rather_than_dropped():
    """`file_get_contents` leaves this file. A slice that said nothing about
    that would read as complete."""
    stripped, _ = strip_annotations(open(LAB).read())
    sink_line = next(n for n, text in enumerate(stripped, 1)
                     if "file_get_contents(" in text)
    result = slice_source(LAB, sink_line, depth=2, strip=True)
    assert "file_get_contents" in result.unresolved_calls
    assert any("were not" in note for note in result.notes)


def test_control_flow_is_not_reported_as_an_unexpanded_call():
    """`if (...)` and `foreach (...)` match a call pattern and are not calls.
    A list that named them would bury the sinks that matter."""
    stripped, _ = strip_annotations(open(LAB).read())
    sink_line = next(n for n, text in enumerate(stripped, 1)
                     if "file_get_contents(" in text)
    result = slice_source(LAB, sink_line, depth=2, strip=True)
    assert not ({"if", "foreach", "return", "isset"} & set(result.unresolved_calls))
