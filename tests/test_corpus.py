"""The corpus must describe the sources it claims to describe."""
from ssrefuse.corpus import REPO_ROOT, Corpus
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
    """Grouped per shared region, because each lab has its own.

    Asserting over the first sharer alone passed for as long as there was one
    lab and would have started reporting the second lab's helper as missing
    from the first lab's attribution.
    """
    corpus = Corpus()
    sharers = [v for v in corpus.variants if v.uses_shared]
    assert sharers, "the corpus is supposed to contain an interprocedural variant"
    regions: dict[tuple[str, str], list] = {}
    for variant in sharers:
        for name, (start, _end) in variant.shared_spans.items():
            regions.setdefault((variant.file, name), []).append((variant, start))
    assert len(regions) >= 2, "every lab is expected to have one shared sink"
    for (file, name), callers in regions.items():
        start = callers[0][1]
        owners = {v.id for v in corpus.attribute_all(file, start + 1)}
        assert len(owners) >= 2, f"{name}: shared sink attributed only to {owners}"
        for variant, _ in callers:
            assert variant.id in owners, f"{name} does not attribute to {variant.id}"


def test_every_app_in_the_corpus_has_variants_and_a_source_file():
    corpus = Corpus()
    assert len(corpus.apps) >= 2, "the corpus is supposed to span more than one language"
    for name, app in corpus.apps.items():
        assert corpus.for_app(name), f"{name} has no variants"
        assert (REPO_ROOT / app.file).exists(), f"{name}: {app.file} is missing"


def test_a_line_outside_every_region_is_unattributed():
    assert Corpus().attribute("corpus/labs/flask_ssrf/app.py", 1) is None
