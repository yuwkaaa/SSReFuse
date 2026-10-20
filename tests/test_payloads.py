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
