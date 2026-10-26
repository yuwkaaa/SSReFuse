"""How a lab is judged to be up, pinned on the bug that made it lie.

The probe refused to start the PHP lab with `lab never printed 'Development
Server'` and printed, directly underneath, a log containing that exact string.
The cause was `line.startswith(marker)` against a server that timestamps every
line it writes, so the marker can never be at column zero.

The fix that was *not* taken is the one these tests exist to prevent: changing
`startswith` to `in` for every lab. A substring match also matches a line that
merely mentions the marker -- an error message quoting it, a path containing it
-- so the mode is declared per app instead, and the stricter one stays the
default.
"""
import pytest

from ssrefuse.corpus import App, Corpus
from ssrefuse.harness.probe import LabProcess

# The real thing, copied from a failed run rather than invented.
PHP_BANNER = ("[Sun Oct 25 22:48:33 2026] PHP 8.4.27 Development Server "
              "(http://127.0.0.1:19082) started")


def _lab(tmp_path, **kwargs) -> LabProcess:
    app = App(name="t", lang="php", file="x", start=["true"],
              ready_marker=kwargs.pop("marker", "Development Server"),
              **kwargs)
    return LabProcess(app, 19999, tmp_path)


def test_a_timestamped_banner_matches_under_contains(tmp_path):
    assert _lab(tmp_path, ready_match="contains")._marks_ready(PHP_BANNER)


def test_the_same_banner_does_not_match_under_prefix(tmp_path):
    """The control. Without this, the test above would pass whatever the mode
    did, and the declared mode would not be shown to carry any weight."""
    assert not _lab(tmp_path, ready_match="prefix")._marks_ready(PHP_BANNER)


def test_prefix_is_the_default(tmp_path):
    """A new lab that forgets to declare a mode gets the stricter one."""
    assert _lab(tmp_path).app.ready_match == "prefix"
    assert not _lab(tmp_path)._marks_ready(PHP_BANNER)


def test_prefix_rejects_a_line_that_only_mentions_the_marker(tmp_path):
    """Why `in` was not applied to every lab. Both of these would satisfy a
    substring match, and neither means the server is up."""
    for line in (f"error: expected 'LAB-READY' but the port was closed",
                 "waiting for LAB-READY ..."):
        assert not _lab(tmp_path, marker="LAB-READY",
                        ready_match="prefix")._marks_ready(line)


def test_contains_accepts_them_which_is_the_cost_of_the_looser_mode(tmp_path):
    """Stated rather than hidden: `contains` is weaker, which is exactly why it
    is opt-in and why the port check still has to pass before a lab is ready."""
    assert _lab(tmp_path, marker="LAB-READY",
                ready_match="contains")._marks_ready("waiting for LAB-READY ...")


@pytest.mark.parametrize("name,expected", [("flask_ssrf", "prefix"),
                                           ("node_ssrf", "prefix"),
                                           ("php_ssrf", "contains")])
def test_each_lab_declares_the_mode_its_runtime_needs(name, expected):
    """The configuration, checked. The labs that print their own marker use the
    strict mode; the one that relies on its server's banner does not."""
    assert Corpus().apps[name].ready_match == expected


def test_the_php_lab_declares_the_runtime_floor_that_is_a_security_floor():
    """Serving HTTP from PHP below 8.4.27 serves it from a build affected by
    CVE-2026-109618 and CVE-2026-109619, both unauthenticated RCE at CVSS v4.0
    9.2 -- and this lab is fed attacker-shaped input by design."""
    assert Corpus().apps["php_ssrf"].min_runtime == "8.4.27"


# --- the declared runtime floor, which has to be read or it is decoration ---

def test_version_components_compare_numerically():
    from ssrefuse.harness.probe import _version_tuple
    assert _version_tuple("8.4.27-1") == (8, 4, 27)
    assert _version_tuple("8.4.27") < _version_tuple("8.4.28")
    assert _version_tuple("8.4.9") < _version_tuple("8.4.27"), "string compare, not numeric"
    assert _version_tuple("8.5.0") > _version_tuple("8.4.27")


def test_an_unreadable_version_does_not_compare_as_zero():
    """It must not sort below a floor and let the lab start anyway, and it must
    not sort above one either. `(-1,)` is lower than any real version, so an
    unreadable answer refuses rather than passes."""
    from ssrefuse.harness.probe import _version_tuple
    assert _version_tuple("") == (-1,)
    assert _version_tuple("not-a-version") == (-1,)
    assert _version_tuple("") < _version_tuple("0.0.1")


def test_a_runtime_below_the_floor_refuses_to_measure(tmp_path, monkeypatch):
    lab = _lab(tmp_path, ready_match="contains", min_runtime="8.4.27")
    monkeypatch.setattr("ssrefuse.harness.probe.subprocess.run",
                        lambda *a, **k: type("R", (), {"stdout": "8.4.24"})())
    with pytest.raises(RuntimeError, match="CVE-2026-109618"):
        lab._check_min_runtime()


def test_a_runtime_at_the_floor_is_accepted(tmp_path, monkeypatch):
    """The control. Without it the test above only shows that something raises."""
    lab = _lab(tmp_path, ready_match="contains", min_runtime="8.4.27")
    monkeypatch.setattr("ssrefuse.harness.probe.subprocess.run",
                        lambda *a, **k: type("R", (), {"stdout": "8.4.27-1"})())
    lab._check_min_runtime()
    assert lab.runtime_version == "8.4.27-1"


def test_no_declared_floor_means_no_check_and_no_recorded_version(tmp_path):
    """An empty `runtime_version` in the results means "no floor to check",
    and must not be read as "checked and unknown"."""
    lab = _lab(tmp_path)
    lab._check_min_runtime()
    assert lab.runtime_version == ""


def test_a_declared_floor_with_no_probe_refuses_rather_than_skips(tmp_path):
    """An unenforced floor is worse than no floor: it reads as enforced."""
    lab = _lab(tmp_path, min_runtime="1.0")
    lab.app.lang = "cobol"
    with pytest.raises(RuntimeError, match="no version probe"):
        lab._check_min_runtime()
