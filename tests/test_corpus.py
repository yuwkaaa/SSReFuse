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


def test_the_port_allowlist_variant_has_a_control_that_differs_only_in_the_guard():
    """G17 is the only guard in the corpus that reasons about the port, so its
    row is only readable next to one that does not.

    The control has to match on sink, injection shape and every other guard,
    or the difference between the two rows is not the port check. This is
    pinned because a later edit to either route would quietly turn the
    comparison into a comparison of something else.
    """
    corpus = Corpus()
    pairs = [("py-024", "py-015"), ("js-024", "js-016")]
    for guarded_id, control_id in pairs:
        guarded, control = corpus.by_id(guarded_id), corpus.by_id(control_id)
        assert "G17_port_allowlist" in guarded.guards
        assert "G17_port_allowlist" not in control.guards
        assert set(guarded.guards) - {"G17_port_allowlist"} == set(control.guards), (
            f"{guarded_id} and {control_id} differ in more than the port check")
        assert guarded.sink == control.sink
        assert guarded.payload_kind == control.payload_kind
        assert guarded.app == control.app


def test_every_guard_named_in_the_taxonomy_is_used_by_some_variant():
    """A guard id nobody implements is a row the report can never fill."""
    corpus = Corpus()
    used = {g for v in corpus.variants for g in v.guards}
    declared = set(corpus.meta.get("guards", {}))
    assert not (declared - used), f"declared but never implemented: {sorted(declared - used)}"


def test_the_self_admin_variant_is_a_target_not_a_sink():
    """py-028 and js-028 send no request. A detector reporting them is wrong,
    and the corpus has to say so, or the route would be read as an SSRF sink
    because it has the word admin in it."""
    corpus = Corpus()
    for vid in ("py-028", "js-028"):
        variant = corpus.by_id(vid)
        assert variant.no_sink and variant.label == "safe"
        assert "G14_trusts_source_address" in variant.guards
        assert variant.why_safe


def test_the_webhook_pair_splits_the_check_from_the_fetch():
    """The feature only has a bug because the two halves are separate
    requests. If one route ever did both, the variant would stop being about
    the entry point and start being about the guard."""
    corpus = Corpus()
    for register, deliver in (("py-025", "py-026"), ("js-025", "js-026")):
        reg, del_ = corpus.by_id(register), corpus.by_id(deliver)
        assert reg.no_sink, f"{register} must not fetch: the check lives there"
        assert not del_.no_sink, f"{deliver} is where the fetch happens"
        assert reg.guards and not del_.guards, "the check is on the wrong half"
        assert "steps" in del_.entry, f"{deliver} has to be a two-request flow"


def test_every_entry_point_in_the_taxonomy_is_used():
    corpus = Corpus()
    declared = set(corpus.meta.get("entry_points", {}))
    assert declared, "the entry-point axis is supposed to be declared"
    import yaml
    raw = yaml.safe_load((REPO_ROOT / "corpus/ground-truth.yaml").read_text())
    used = {v.get("entry_point", "E0_parameter") for v in raw["variants"]}
    assert not (declared - used), f"declared but unused: {sorted(declared - used)}"
    assert not (used - declared), f"used but undeclared: {sorted(used - declared)}"
