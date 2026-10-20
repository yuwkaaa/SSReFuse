"""The payload catalog has to keep its control and its instrument separate."""
from ssrefuse.corpus import Corpus
from ssrefuse.harness import payloads as catalog


def test_control_family_exists_and_is_excluded_from_attacks():
    assert catalog.CONTROL_FAMILY in catalog.FAMILY_BY_ID
    assert catalog.CONTROL_FAMILY not in catalog.ATTACK_FAMILIES


def test_instrument_families_are_excluded_from_attacks():
    assert catalog.INSTRUMENT_FAMILIES
    for family in catalog.INSTRUMENT_FAMILIES:
        assert family not in catalog.ATTACK_FAMILIES


def test_every_family_has_at_least_one_concrete_value():
    empty = [f.id for f in catalog.FAMILIES
             if not (f.url_values or f.host_values or f.path_values)]
    assert not empty


def test_declared_bypasses_name_real_families():
    unknown = [(v.id, b) for v in Corpus().variants for b in v.bypasses_declared
               if b not in catalog.FAMILY_BY_ID]
    assert not unknown


def test_expectations_map_to_known_markers():
    for kind in ("url", "host", "path"):
        for payload in catalog.payloads_for_kind(kind):
            assert payload.expected_marker == catalog.EXPECT_MARKERS[payload.expect]


def test_every_family_declares_a_known_axis():
    """The axis is how the catalog answers "what have you covered".

    A family with an axis nobody declared would be invisible in the coverage
    table while still producing cells in the matrix.
    """
    unknown = [(f.id, f.axis) for f in catalog.FAMILIES if f.axis not in catalog.AXES]
    assert not unknown


def test_axis_coverage_counts_match_the_values_that_exist():
    """The coverage table is read as evidence, so it is recomputed here from
    the families rather than trusted."""
    coverage = catalog.axis_coverage()
    assert sum(c["families"] for c in coverage.values()) == len(catalog.FAMILIES)
    counted = sum(c["values"] for c in coverage.values())
    actual = sum(len(f.url_values) + len(f.host_values) + len(f.path_values)
                 for f in catalog.FAMILIES)
    assert counted == actual


def test_every_internal_target_is_reachable_from_some_family():
    """A target nobody aims at is a service that quietly never gets probed."""
    aimed = {expect for kind in ("url", "host", "path")
             for p in catalog.payloads_for_kind(kind) for expect in [p.expect]}
    missed = [t.key for t in catalog.TARGETS if t.key not in aimed]
    assert not missed, f"no payload aims at {missed}"


def test_the_service_range_family_holds_the_address_fixed():
    """B24 is about ports behind one address. A value on another host would
    make a green cell mean something else entirely."""
    from ssrefuse import testbed_spec as spec
    family = catalog.FAMILY_BY_ID["B24_internal_service_range"]
    for value, _expect in family.url_values:
        assert f"//{spec.IP_INTERNAL}:" in value, value


def test_a_family_that_cannot_disclose_is_never_declared_as_a_bypass():
    """Header-gated metadata is scored reached_not_disclosed, which is not a
    bypass, so declaring it on a variant would be an unreproducible claim
    that the evaluator would report forever."""
    withholding = {f.id for f in catalog.FAMILIES if not f.discloses}
    assert withholding, "the catalog is supposed to contain one of these"
    wrong = [(v.id, b) for v in Corpus().variants for b in v.bypasses_declared
             if b in withholding]
    assert not wrong, f"{wrong} declared a family that can never count as a bypass"


def test_every_testbed_service_is_classified_as_internal_or_public():
    """Adding a service to the testbed and forgetting to classify it turns a
    reached target into a quiet no_internal_contact, which reads as a guard
    that held."""
    from ssrefuse.harness import services
    from ssrefuse.harness.probe import INTERNAL_SERVICES, PUBLIC_SERVICES

    known = INTERNAL_SERVICES | PUBLIC_SERVICES | {"dns", "dns-oob"}
    names = ([name for name, *_ in services.HTTP_SERVICES]
             + [name for name, *_ in services.LINE_SERVICES])
    assert not [n for n in names if n not in known]


def test_every_internal_canary_belongs_to_some_expectation():
    """A marker the prober can see in a body but cannot name is a hit it
    cannot attribute."""
    from ssrefuse import testbed_spec as spec
    named = set(catalog.EXPECT_MARKERS.values())
    assert not [m for m in spec.INTERNAL_MARKERS if m not in named]



def test_static_only_sinks_are_all_marked_and_the_matcher_ignores_prose():
    """The marker scan is an extractor, so it gets a control.

    A sentence of documentation that mentions the marker must not be read as
    a marker: that would inflate the expected count and turn a rule that
    found everything into a rule that missed something, or the reverse.
    """
    from ssrefuse.evaluation.sinks import SINK_RE, scan_markers

    markers = scan_markers()
    assert len(markers) == 21, [m.name for m in markers]
    assert len({m.name for m in markers}) == len(markers), "marker names must be unique"
    languages = {m.file.rsplit(".", 1)[-1] for m in markers}
    assert {"php", "java", "js"} <= languages, languages

    # The exact line of prose that lives in each static-only header.
    prose = " * sinks is marked with @ssrefuse:sink so the evaluator can say"
    assert SINK_RE.match(prose) is None
    assert SINK_RE.match("    // @ssrefuse:sink php-fopen").group(1) == "php-fopen"
    assert SINK_RE.match("    # @ssrefuse:sink py-thing").group(1) == "py-thing"


def test_the_brief_named_sinks_are_actually_in_the_rules():
    """file_get_contents and URLConnection are named in the assignment, so a
    rule set that stopped matching them would fail a requirement silently."""
    from ssrefuse.corpus import REPO_ROOT

    php = (REPO_ROOT / "rules/semgrep/php-inventory.yaml").read_text()
    java = (REPO_ROOT / "rules/semgrep/java-inventory.yaml").read_text()
    python = (REPO_ROOT / "rules/semgrep/python-inventory.yaml").read_text()
    assert "file_get_contents" in php
    assert "curl_exec" in php
    assert "openConnection" in java
    assert "requests.$M" in python
