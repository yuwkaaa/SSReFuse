"""The .env loader, pinned on the rules that matter for a secret.

A loader for keys gets tested on three things and nothing else: it must not
override a deliberate export, it must not print a value, and it must parse the
shapes people actually write.
"""
import os

from ssrefuse import env


def test_an_exported_variable_wins_over_the_file(tmp_path, monkeypatch):
    """An export is a deliberate act. A file on disk must not undo it."""
    path = tmp_path / ".env"
    path.write_text("SSREFUSE_TEST_KEY=from-file\n")
    path.chmod(0o600)
    monkeypatch.setenv("SSREFUSE_TEST_KEY", "from-shell")

    report = env.load(path)
    assert report["SSREFUSE_TEST_KEY"] == "kept"
    assert os.environ["SSREFUSE_TEST_KEY"] == "from-shell"


def test_a_missing_variable_is_set_from_the_file(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_text("SSREFUSE_TEST_KEY=from-file\n")
    path.chmod(0o600)
    monkeypatch.delenv("SSREFUSE_TEST_KEY", raising=False)

    report = env.load(path)
    assert report["SSREFUSE_TEST_KEY"] == "set"
    assert os.environ["SSREFUSE_TEST_KEY"] == "from-file"


def test_an_empty_value_is_reported_rather_than_set(tmp_path, monkeypatch):
    """A blank key is the state the template ships in, and a run that treats
    it as present fails later and further from the cause."""
    path = tmp_path / ".env"
    path.write_text("SSREFUSE_TEST_KEY=\n")
    path.chmod(0o600)
    monkeypatch.delenv("SSREFUSE_TEST_KEY", raising=False)

    assert env.load(path)["SSREFUSE_TEST_KEY"] == "empty"
    assert "SSREFUSE_TEST_KEY" not in os.environ


def test_the_shapes_people_write_all_parse():
    parsed = env.parse(
        "# a comment\n"
        "\n"
        "export QUOTED=\"with spaces\"\n"
        "SINGLE='sk-single'\n"
        "PLAIN=sk-plain\n"
        "  SPACED   =   sk-spaced   \n"
        "WITH_EQUALS=sk-a=b=c\n"
        "no_equals_line\n"
    )
    assert parsed == {
        "QUOTED": "with spaces",
        "SINGLE": "sk-single",
        "PLAIN": "sk-plain",
        "SPACED": "sk-spaced",
        "WITH_EQUALS": "sk-a=b=c",
    }


def test_the_report_never_carries_a_value(tmp_path, monkeypatch):
    """`describe` is printed. If a value could reach it, the key would end up
    in a terminal, a scrollback and very likely a screenshot."""
    path = tmp_path / ".env"
    path.write_text("SSREFUSE_TEST_KEY=sk-super-secret-value\n")
    path.chmod(0o600)
    monkeypatch.delenv("SSREFUSE_TEST_KEY", raising=False)

    line = env.describe(env.load(path))
    assert "sk-super-secret-value" not in line
    assert "SSREFUSE_TEST_KEY=set" in line


def test_loose_permissions_are_reported_not_ignored(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    path.write_text("SSREFUSE_TEST_KEY=x\n")
    path.chmod(0o644)
    monkeypatch.delenv("SSREFUSE_TEST_KEY", raising=False)

    report = env.load(path)
    assert "readable beyond its owner" in report["_permissions"]


def test_a_missing_file_is_not_an_error():
    assert env.load("/nonexistent/.env") == {}


def test_the_real_env_file_is_ignored_by_git():
    """The template is committed; the file with the key in it is not."""
    from ssrefuse.corpus import REPO_ROOT

    ignored = (REPO_ROOT / ".gitignore").read_text().splitlines()
    assert ".env" in [line.strip() for line in ignored]
    assert (REPO_ROOT / ".env.example").exists(), "the template should be committed"


def test_the_effort_is_part_of_the_cache_key():
    """The same prompt at two thinking budgets is two measurements.

    If the key ignored the effort, the second arm of the ablation would be
    served the first arm's answers and the comparison would report a
    difference of zero, which is the most convincing wrong number available.
    """
    from ssrefuse.llm.cache import ResponseCache
    from ssrefuse.llm.client import LLMClient

    cache = ResponseCache(enabled=False)
    quiet = LLMClient(provider="mock", reasoning_effort="none", cache=cache)
    loud = LLMClient(provider="mock", reasoning_effort="high", cache=cache)

    from ssrefuse.llm.cache import cache_key
    key_quiet = cache_key(quiet.provider, quiet.model, "p", quiet.temperature,
                          "s|effort=none")
    key_loud = cache_key(loud.provider, loud.model, "p", loud.temperature,
                         "s|effort=high")
    assert key_quiet != key_loud


def test_an_unknown_effort_is_refused_at_construction():
    from ssrefuse.llm.client import LLMUnavailable, LLMClient
    import pytest

    with pytest.raises(LLMUnavailable):
        LLMClient(provider="mock", reasoning_effort="medium")


def test_the_model_ids_in_use_are_not_the_retired_ones():
    """`deepseek-chat` and `deepseek-reasoner` selected non-thinking and
    thinking mode and were scheduled for retirement on 2026-07-24. Thinking is
    a request parameter now, so a default that still names them would be a run
    against a name that may no longer resolve."""
    from ssrefuse.llm.client import PROVIDERS

    deepseek = PROVIDERS["deepseek"]
    assert deepseek["default_model"] not in ("deepseek-chat", "deepseek-reasoner")
    assert "deepseek-chat" not in deepseek["models"]
    assert "deepseek-reasoner" not in deepseek["models"]
    assert deepseek["supports_reasoning_effort"] is True


def test_openrouter_points_at_openrouter():
    """The old project configuration in circulation set an OpenRouter key
    beside a DeepSeek base URL, which sends the key to the wrong host."""
    from ssrefuse.llm.client import PROVIDERS

    assert PROVIDERS["openrouter"]["base_url"].startswith("https://openrouter.ai")
    assert PROVIDERS["openrouter"]["key_env"] == "OPENROUTER_API_KEY"
    assert PROVIDERS["deepseek"]["base_url"].startswith("https://api.deepseek.com")
