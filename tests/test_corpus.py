"""The corpus must describe the sources it claims to describe."""
from ssrefuse.corpus import Corpus
from ssrefuse.harness.payloads import FAMILY_BY_ID


def test_corpus_validates_against_its_sources():
    report = Corpus().validate(set(FAMILY_BY_ID))
    assert not report.problems, report.render()


def test_every_variant_has_a_line_span():
    corpus = Corpus()
    missing = [v.id for v in corpus.variants if not v.line_start]
    assert not missing, f"no source marker for {missing}"


def test_safe_variants_state_a_reason():
    corpus = Corpus()
    unexplained = [v.id for v in corpus.variants if v.label == "safe" and not v.why_safe]
    assert not unexplained


def test_shared_region_attributes_to_every_declared_caller():
    corpus = Corpus()
    sharers = [v for v in corpus.variants if v.uses_shared]
    assert sharers, "the corpus is supposed to contain an interprocedural variant"
    variant = sharers[0]
    start, end = next(iter(variant.shared_spans.values()))
    owners = {v.id for v in corpus.attribute_all(variant.file, start + 1)}
    assert len(owners) >= 2, f"shared sink attributed only to {owners}"
    for other in sharers:
        assert other.id in owners


def test_a_line_outside_every_region_is_unattributed():
    assert Corpus().attribute("corpus/labs/flask_ssrf/app.py", 1) is None
