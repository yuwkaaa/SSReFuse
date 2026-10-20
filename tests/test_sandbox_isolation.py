"""The sandbox must be unable to reach anything real.

Marked slow because it builds the namespace and starts the testbed. It is the
test that justifies every other result: the labs fetch a cloud metadata address
and an internal admin service, and this is the evidence that both of those are
local fakes with no route out.
"""
import pytest

from ssrefuse.harness.sandbox import SandboxUnavailable, check_support, run_in_sandbox


@pytest.mark.slow
def test_sandbox_is_hermetic_and_the_testbed_answers():
    try:
        check_support()
    except SandboxUnavailable as exc:
        pytest.skip(f"namespaces unavailable here: {exc}")

    result = run_in_sandbox({"job": "selftest"}, "results/selftest")
    assert result["ok"], result.get("error")

    isolation = result["isolation"]
    assert isolation["hermetic"] is True
    assert not isolation["tcp_1.1.1.1:443"].startswith("CONNECTED")
    assert not isolation["dns:example.com"].startswith("RESOLVED")

    probes = result["probes"]
    assert probes["internal-by-ip"]["marker"] == "SSREFUSE-INTERNAL-ADMIN-SECRET"
    assert probes["metadata-by-ip"]["marker"] == "SSREFUSE-METADATA-CREDENTIALS"
    assert probes["public-allowed"]["marker"] == "SSREFUSE-PUBLIC-BENIGN"

    sequence = probes["rebind_sequence"]
    assert len(set(sequence)) == 2, f"rebinding did not alternate: {sequence}"
