"""A slice must not hand the answer to the model.

The lab sources are documented, and the documentation names the vulnerability
and the technique that defeats it. If any of that reaches a prompt, the LLM pass
measures how well a model reads our comments.

The leakage check is generated from the labs themselves rather than from a list
of words: every docstring and comment in every lab source is collected at test
time, and no substantial line of any of them may appear in any slice.
Identifier names and the application's own error strings are left alone on
purpose -- `ALLOWED_HOST` and "host not allowlisted" are what a real
application looks like, and reasoning from them is analysis, not leakage.

Both labs are covered, and the prose of each is checked against the slices of
its own file. Collecting the prose per language is what keeps the check honest
when a language is added: a lab whose prose extractor returns nothing would
make every slice of it pass, so `test_every_lab_is_actually_documented` fails
on an empty extraction rather than letting the suite prove nothing.
"""
import ast
import io
import tokenize

import pytest

from ssrefuse.corpus import REPO_ROOT, Corpus
from ssrefuse.slicing import slice_python, slice_source, strip_annotations
from ssrefuse.slicing_js import BLOCK_COMMENT, LINE_COMMENT, classify

MARKERS = ("@ssrefuse:begin", "@ssrefuse:end")


def _python_prose(source: str) -> list[str]:
    out: list[str] = []
    tree = ast.parse(source)
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)) or not body:
            continue
        first = body[0]
        if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)):
            out += first.value.value.splitlines()
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.COMMENT:
            out.append(token.string.lstrip("# "))
    return out


def _javascript_prose(source: str) -> list[str]:
    """Every comment line, taken from the same scanner the slicer uses."""
    kinds = classify(source)
    out: list[str] = []
    current: list[str] = []
    for index, char in enumerate(source):
        if kinds[index] in (LINE_COMMENT, BLOCK_COMMENT):
            current.append(char)
        if char == "\n" and current:
            out.append("".join(current).lstrip("/*! ").rstrip())
            current = []
    if current:
        out.append("".join(current).lstrip("/*! ").rstrip())
    return out


# PHP is read with the JavaScript scanner on purpose and not by accident: `//`
# and `/* */` are the same lexical forms in both, so the scanner that finds a
# comment in one finds it in the other. What it does NOT know about is PHP's
# third comment form, `#`, and a lab that used it would have that prose
# silently dropped from the leakage corpus -- a weaker check that still passes.
# `test_no_lab_uses_a_comment_form_the_scanner_cannot_see` holds that line.
EXTRACTORS = {"python": _python_prose, "javascript": _javascript_prose,
              "php": _javascript_prose}
SUFFIX_LANG = {".py": "python", ".pyi": "python", ".js": "javascript",
               ".mjs": "javascript", ".cjs": "javascript", ".php": "php"}


def _prose_for(path) -> list[str]:
    source = path.read_text()
    if path.suffix not in SUFFIX_LANG:
        # Said here rather than defaulted to Python. A new lab language that
        # fell through to the Python tokenizer would either crash or, worse,
        # return nothing and quietly leave that lab out of the leakage corpus.
        raise AssertionError(
            f"no prose extractor for {path.suffix!r} ({path}). Add one to "
            f"EXTRACTORS and SUFFIX_LANG; a lab with no extractor is a lab "
            f"whose docstrings are never checked for leaking the answer.")
    extractor = EXTRACTORS[SUFFIX_LANG[path.suffix]]
    # Only lines with enough words to be prose; a one-word fragment would match
    # ordinary code by accident.
    return [line.strip() for line in extractor(source) if len(line.split()) >= 5]


CORPUS = Corpus()
PROSE = {app.file: _prose_for(REPO_ROOT / app.file) for app in CORPUS.apps.values()}
LAB = REPO_ROOT / "corpus/labs/flask_ssrf/app.py"


@pytest.mark.parametrize("app_file", sorted(PROSE))
def test_every_lab_is_actually_documented(app_file):
    assert len(PROSE[app_file]) > 40, (
        f"{app_file}: if the lab has no prose, or the extractor cannot see it, "
        f"the leakage check below proves nothing")


@pytest.mark.parametrize("variant_id", [v.id for v in CORPUS.variants])
def test_slice_contains_no_label_leakage(variant_id):
    variant = CORPUS.by_id(variant_id)
    text = slice_source(REPO_ROOT / variant.file, variant.line_start + 1).render()
    leaked = [line for line in PROSE[variant.file] if line and line in text]
    leaked += [marker for marker in MARKERS if marker in text]
    assert not leaked, f"{variant_id}: slice leaks {leaked[:3]}"


def test_stripping_preserves_line_numbers():
    source = LAB.read_text()
    lines, removed = strip_annotations(source)
    assert len(lines) == len(source.splitlines())
    assert removed["docstring_lines"] > 0 and removed["comment_lines"] > 0


def test_interprocedural_slice_reaches_the_real_sink():
    variant = CORPUS.by_id("py-003")
    text = slice_python(REPO_ROOT / variant.file, variant.line_start + 3).render()
    assert "_fetch_remote" in text
    assert "requests.get(target" in text, "the slice omitted the sink itself"


def test_the_guard_values_are_in_the_slice():
    """A guard cannot be judged without the values it compares against."""
    variant = CORPUS.by_id("py-007")
    text = slice_python(REPO_ROOT / variant.file, variant.line_start + 4).render()
    assert "BLOCKED_HOSTS" in text
    assert "169.254.169.254" in text, "the denylist contents were sliced away"


def test_keeping_comments_is_opt_in_and_leaks_as_expected():
    """The opt-out exists to measure what the documentation is worth to a model."""
    variant = CORPUS.by_id("py-001")
    kept = slice_python(REPO_ROOT / variant.file, variant.line_start + 1, strip=False)
    assert not kept.stripped
    leaked = [line for line in PROSE[variant.file] if line and line in kept.render()]
    assert leaked, "with stripping off the prose should be visible again"


def test_judge_can_widen_the_slice_on_request():
    variant = CORPUS.by_id("py-001")
    narrow = slice_python(REPO_ROOT / variant.file, variant.line_start + 1)
    wider = slice_python(REPO_ROOT / variant.file, variant.line_start + 1,
                         include_functions=["_fetch_remote"],
                         include_values=["BLOCKED_HOSTS"])
    assert wider.line_count() > narrow.line_count()
    assert "_fetch_remote" in wider.render() and "BLOCKED_HOSTS" in wider.render()


def test_asking_for_something_absent_is_recorded_not_ignored():
    variant = CORPUS.by_id("py-001")
    result = slice_python(REPO_ROOT / variant.file, variant.line_start + 1,
                          include_functions=["no_such_function"])
    assert any("no_such_function" in note for note in result.notes)


def test_the_dispatcher_refuses_a_language_it_has_no_slicer_for():
    """An unknown extension must not fall through to the Python parser."""
    with pytest.raises(ValueError):
        slice_source(REPO_ROOT / "README.md", 1)


@pytest.mark.parametrize("app_file", sorted(PROSE))
def test_no_lab_uses_a_comment_form_the_scanner_cannot_see(app_file):
    """The assumption behind reading PHP with the JavaScript scanner.

    PHP also spells a line comment `#`, and the scanner does not know that
    form. A lab that used it would keep its prose out of the leakage corpus,
    which makes this whole module quietly weaker while still passing. Checked
    for every lab rather than only the PHP one, since the next language may
    share the problem.
    """
    source = (REPO_ROOT / app_file).read_text()
    if app_file.endswith(".py"):
        return                      # `#` is the only comment form Python has
    offenders = [
        number for number, line in enumerate(source.splitlines(), 1)
        if line.lstrip().startswith("#") and len(line.split()) >= 5
    ]
    assert not offenders, (
        f"{app_file} uses `#` comments on line(s) {offenders}, which the "
        f"JavaScript comment scanner does not recognise. That prose would be "
        f"missing from the leakage corpus. Rewrite them as `//`, or teach the "
        f"scanner the form.")
