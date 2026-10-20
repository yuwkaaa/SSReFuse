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


def test_a_detector_run_is_unusable_when_any_one_control_is_silent():
    """One total over two languages would hide a half-loaded tier.

    A tier whose Python rules work and whose JavaScript rules match nothing
    still reports a healthy total, and its JavaScript zeros would be read as a
    clean corpus.
    """
    from ssrefuse.detectors.base import DetectorRun

    both = DetectorRun(detector="t", config="c",
                       control_by_file={"python.py": 1, "javascript.js": 2})
    assert both.usable and both.status() == "ok" and both.control_findings == 3

    half = DetectorRun(detector="t", config="c",
                       control_by_file={"python.py": 1, "javascript.js": 0})
    assert not half.usable
    assert "javascript.js" in half.status()

    none = DetectorRun(detector="t", config="c")
    assert not none.usable and "no positive control" in none.status()


def test_a_service_that_withholds_its_secret_is_neither_bypass_nor_block():
    """Header-gated cloud metadata: the request arrived, the secret did not.

    Scoring this as reached_internal would credit the attacker with a
    disclosure that did not happen; scoring it as blocked would credit the
    application with a guard it does not have. It is the cloud's own
    mitigation, and it gets to be its own verdict.
    """
    gated = Payload("B30_metadata_header_gated",
                    "http://169.254.169.254/computeMetadata/v1/", "url",
                    "metadata_guarded", spec.MARKER_METADATA_GUARDED, discloses=False)
    attempt = Attempt(status=200, log_rows=[{"service": "metadata", "path": "/computeMetadata/v1/"}])
    verdict, evidence = _classify(VARIANT, gated, attempt)
    assert verdict == "reached_not_disclosed"
    assert "the application did not stop this" in evidence

    # The same shape with a family that does disclose stays a bypass, so the
    # new verdict cannot swallow the old one.
    openly = Payload("B15_metadata_service", "http://169.254.169.254/latest/meta-data/",
                     "url", "metadata", spec.MARKER_METADATA)
    assert _classify(VARIANT, openly, attempt)[0] == "reached_internal"


def test_the_new_verdict_does_not_count_as_a_bypass():
    from ssrefuse.evaluation.dynamic import BYPASS_VERDICTS, CELL_SYMBOL, VERDICT_RANK

    assert "reached_not_disclosed" not in BYPASS_VERDICTS
    assert "reached_not_disclosed" in CELL_SYMBOL
    # Ranked below a real disclosure and above everything weaker, so a family
    # with several values reports the strongest thing that actually happened.
    assert (VERDICT_RANK["reached_internal"] > VERDICT_RANK["reached_not_disclosed"]
            > VERDICT_RANK["oob_confirmed"])
