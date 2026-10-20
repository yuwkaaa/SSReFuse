"""The prober's verdicts must stay distinguishable.

Collapsing "the guard refused it", "the client raised", and "the request went
somewhere harmless" into one bucket is what makes a bypass matrix overstate a
filter, so each path is pinned here.
"""
from ssrefuse import testbed_spec as spec
from ssrefuse.corpus import Corpus
from ssrefuse.harness.probe import Attempt, _classify
from ssrefuse.harness.payloads import Payload

VARIANT = Corpus().by_id("py-001")
INTERNAL = Payload("B01_plain_loopback", "http://127.0.0.1:19001/admin", "url",
                   "internal", spec.MARKER_INTERNAL)
BENIGN = Payload("B00_benign_allowed", "http://public.ssrefuse.test/", "url",
                 "benign", spec.MARKER_BENIGN)


def test_marker_in_body_is_a_bypass():
    attempt = Attempt(status=200, marker_in_body=spec.MARKER_INTERNAL)
    assert _classify(VARIANT, INTERNAL, attempt)[0] == "reached_internal"


def test_blind_hit_is_proven_by_the_target_log():
    attempt = Attempt(status=200, log_rows=[{"service": "internal-admin", "path": "/admin"}])
    assert _classify(VARIANT, INTERNAL, attempt)[0] == "reached_internal"


def test_application_refusal_is_blocked_not_safe():
    attempt = Attempt(status=403, blocked_reason="denylisted host 127.0.0.1")
    verdict, evidence = _classify(VARIANT, INTERNAL, attempt)
    assert verdict == "blocked"
    assert "denylisted" in evidence


def test_client_failure_is_not_a_blocked_request():
    attempt = Attempt(error="ConnectionError: refused")
    assert _classify(VARIANT, INTERNAL, attempt)[0] == "sink_error"


def test_reaching_a_public_host_is_not_a_bypass():
    attempt = Attempt(status=200, log_rows=[{"service": "public-site", "path": "/"}])
    verdict, evidence = _classify(VARIANT, INTERNAL, attempt)
    assert verdict == "no_internal_contact"
    assert "public-site" in evidence


def test_control_payload_is_confirmed_by_the_log_when_the_body_is_discarded():
    attempt = Attempt(status=200, log_rows=[{"service": "public-site", "path": "/"}])
    assert _classify(VARIANT, BENIGN, attempt)[0] == "reached_benign"
