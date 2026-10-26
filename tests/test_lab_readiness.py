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
