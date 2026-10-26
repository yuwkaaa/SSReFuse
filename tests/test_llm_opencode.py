"""The opencode transport, pinned on the things it is allowed to be silent about.

This transport reports less than a vendor API does -- no token usage, no
chain of thought, no temperature, no JSON mode -- so every test here is about
the same risk: an absence must stay an absence. A run that never learned what
it spent must not read, anywhere downstream, like a run that spent nothing.
"""
import json

import pytest

from ssrefuse.llm import opencode
from ssrefuse.llm.cache import ResponseCache
from ssrefuse.llm.client import LLMClient, LLMUnavailable


# --- the model reference ----------------------------------------------------

def test_a_provider_slash_model_pair_splits():
    assert opencode.split_model_ref("opencode-go/deepseek-v4.1-flash") == (
        "opencode-go", "deepseek-v4.1-flash")


def test_a_bare_model_name_is_refused_with_the_shape_in_the_message():
    """`deepseek-v4.1-flash` is ambiguous here: the same model exists on a
    subscription provider and on a pay-per-token one, at different prices."""
    with pytest.raises(opencode.OpencodeUnavailable) as caught:
        opencode.split_model_ref("deepseek-v4.1-flash")
    assert "provider/model" in str(caught.value)


def test_a_variant_suffix_is_refused_rather_than_honoured():
    """opencode's own CLI takes `provider/model#variant`. Accepting it here
    would give the thinking budget two places to come from, and the arm name
    and cache key are built from only one of them."""
    with pytest.raises(opencode.OpencodeUnavailable) as caught:
        opencode.split_model_ref("opencode-go/deepseek-v4.1-flash#high")
    assert "--effort" in str(caught.value)


# --- the thinking budget ----------------------------------------------------

def test_none_maps_to_no_variant_and_not_to_low():
    """`none` means the model's own default. Mapping it to `low` would put a
    number on the ablation's baseline that the baseline did not run at."""
    assert opencode.VARIANT_FOR_EFFORT["none"] is None
    assert opencode.VARIANT_FOR_EFFORT["low"] == "low"


def test_there_is_no_off_variant_so_the_client_refuses_that_arm():
    """The real non-thinking arm cannot be run on this transport, and the
    failure has to be loud: an `off` column measured at the provider default
    is worse than a missing one."""
    assert "off" not in opencode.VARIANT_FOR_EFFORT
    client = LLMClient(provider="opencode", reasoning_effort="off",
                       cache=ResponseCache(enabled=False))
    with pytest.raises(LLMUnavailable) as caught:
        client._opencode_variant()
    assert "--provider deepseek" in str(caught.value)


# --- what the transport cannot report --------------------------------------

def test_the_client_declares_the_absences_rather_than_implying_zeros():
    client = LLMClient(provider="opencode", cache=ResponseCache(enabled=False))
    described = client.describe()
    assert described["transport"] == "opencode"
    assert described["usage_reported"] is False
    assert described["temperature_sent"] is False
    assert described["capabilities"]["json_mode"] is False
    assert described["capabilities"]["reasoning_content_returned"] is False


def test_a_vendor_api_arm_still_claims_its_accounting(monkeypatch):
    """The control for the test above: the flag has to be able to come out
    true, or it is not reporting anything.

    It is asserted after an answer rather than on a fresh client, because the
    flag is a measurement now -- "every answer served came with an
    accounting" -- and a client that has served none has measured nothing.
    """
    client = LLMClient(provider="deepseek", cache=ResponseCache(enabled=False))
    monkeypatch.setenv("DEEPSEEK_API_KEY", "not-a-real-key")

    class _Payload:
        status_code = 200
        text = ""

        @staticmethod
        def json():
            return {"choices": [{"message": {"content": '{"verdict": "safe"}'}}],
                    "usage": {"prompt_tokens": 11, "completion_tokens": 7}}

    monkeypatch.setattr("ssrefuse.llm.client.requests.post",
                        lambda *a, **k: _Payload())
    completion = client.complete("a prompt")

    assert completion.usage_reported is True
    described = client.describe()
    assert described["usage_reported"] is True
    assert described["answers_missing_usage"] == 0
    assert described["temperature_sent"] is True


def test_a_two_hundred_that_carries_no_usage_is_not_a_free_call(monkeypatch):
    """A proxy that strips `usage` is a real thing, and the flag has to follow
    the payload rather than the provider's name -- otherwise a stripped
    accounting reads as a run that cost nothing."""
    client = LLMClient(provider="deepseek", cache=ResponseCache(enabled=False))
    monkeypatch.setenv("DEEPSEEK_API_KEY", "not-a-real-key")

    class _Payload:
        status_code = 200
        text = ""

        @staticmethod
        def json():
            return {"choices": [{"message": {"content": '{"verdict": "safe"}'}}]}

    monkeypatch.setattr("ssrefuse.llm.client.requests.post",
                        lambda *a, **k: _Payload())
    assert client.complete("a prompt").usage_reported is False
    assert client.describe()["answers_missing_usage"] == 1


def test_an_answer_served_from_cache_keeps_the_absence(tmp_path, monkeypatch):
    """The one that would rot quietly. A cached opencode answer replayed as a
    reported zero would turn a blank cost column into a measured one on the
    second run, with nothing in the output to say so."""
    cache = ResponseCache(directory=tmp_path, enabled=True)
    client = LLMClient(provider="opencode", model="opencode-go/deepseek-v4.1-flash",
                       cache=cache)

    class FakeTransport:
        def resolve(self, ref, variant=None):
            return {"providerID": "opencode-go", "id": "deepseek-v4.1-flash"}

        def generate(self, prompt, ref, variant=None):
            return '{"verdict": "safe"}'

    monkeypatch.setattr(client, "_opencode_transport", lambda: FakeTransport())

    first = client.complete("a prompt", system="a system prompt")
    assert first.cached is False
    assert first.usage_reported is False

    second = client.complete("a prompt", system="a system prompt")
    assert second.cached is True
    assert second.usage_reported is False, "a cache hit invented an accounting"


def test_the_effort_is_in_the_cache_key_so_two_arms_do_not_share_answers(tmp_path,
                                                                        monkeypatch):
    cache = ResponseCache(directory=tmp_path, enabled=True)
    answers = iter(['{"verdict": "safe"}', '{"verdict": "vulnerable"}'])

    class FakeTransport:
        def resolve(self, ref, variant=None):
            return {}

        def generate(self, prompt, ref, variant=None):
            return next(answers)

    def client_at(effort):
        client = LLMClient(provider="opencode", reasoning_effort=effort, cache=cache,
                           model="opencode-go/deepseek-v4.1-flash")
        monkeypatch.setattr(client, "_opencode_transport", lambda: FakeTransport())
        return client

    low = client_at("low").complete("same prompt")
    high = client_at("high").complete("same prompt")
    assert high.cached is False, "the high arm was served the low arm's answer"
    assert low.text != high.text


# --- failure modes ---------------------------------------------------------

class _Response:
    def __init__(self, status_code, payload=None, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text or json.dumps(payload or {})

    def json(self):
        return self._payload


def _transport(monkeypatch, response):
    transport = opencode.OpencodeTransport(server="http://127.0.0.1:1",
                                           password="not-used")
    monkeypatch.setattr(transport, "_request", lambda *a, **k: response)
    return transport


def test_a_spent_budget_is_raised_and_not_retried(monkeypatch):
    """`Insufficient account funds` is terminal. A retry loop against it turns
    one readable error into four and buries the sentence that says what to do."""
    transport = _transport(monkeypatch, _Response(
        503, text='{"message":"Upstream request failed: Insufficient account funds"}'))
    with pytest.raises(opencode.OpencodeUnavailable) as caught:
        transport.generate("p", "opencode/deepseek-v4.1-flash")
    assert "budget" in str(caught.value).lower()


def test_a_two_hundred_with_no_text_is_a_failed_call_not_an_empty_verdict(monkeypatch):
    transport = _transport(monkeypatch, _Response(200, {"data": {"text": ""}}))
    with pytest.raises(opencode.OpencodeUnavailable) as caught:
        transport.generate("p", "opencode-go/deepseek-v4.1-flash")
    assert "no text" in str(caught.value)


def test_an_undeclared_variant_is_caught_before_a_prompt_is_spent(monkeypatch):
    transport = opencode.OpencodeTransport(server="http://127.0.0.1:1",
                                            password="not-used")
    monkeypatch.setattr(transport, "models", lambda refresh=False: [
        {"providerID": "opencode-go", "modelID": "deepseek-v4-pro",
         "status": "active", "enabled": True,
         "variants": [{"id": "high"}, {"id": "max"}]}])
    assert transport.resolve("opencode-go/deepseek-v4-pro", "high")["enabled"] is True
    with pytest.raises(opencode.OpencodeUnavailable) as caught:
        transport.resolve("opencode-go/deepseek-v4-pro", "low")
    assert "does not declare" in str(caught.value)


def test_an_unreachable_model_lists_what_is_reachable(monkeypatch):
    transport = opencode.OpencodeTransport(server="http://127.0.0.1:1",
                                            password="not-used")
    monkeypatch.setattr(transport, "models", lambda refresh=False: [
        {"providerID": "opencode-go", "modelID": "deepseek-v4.1-flash",
         "status": "active", "enabled": True, "variants": []}])
    with pytest.raises(opencode.OpencodeUnavailable) as caught:
        transport.resolve("opencode-go/gpt-6-luna")
    assert "opencode-go/deepseek-v4.1-flash" in str(caught.value)


# --- the local server address and password ---------------------------------

def test_an_explicit_server_address_wins_over_asking_opencode(monkeypatch):
    monkeypatch.setenv("SSREFUSE_OPENCODE_SERVER", "http://127.0.0.1:4242/")
    assert opencode.discover_server() == "http://127.0.0.1:4242"


def test_a_missing_service_file_says_how_to_make_one(tmp_path):
    with pytest.raises(opencode.OpencodeUnavailable) as caught:
        opencode.service_password(tmp_path / "service.json")
    assert "opencode service start" in str(caught.value)


def test_the_password_is_read_from_the_override_path(tmp_path, monkeypatch):
    path = tmp_path / "service.json"
    path.write_text(json.dumps({"password": "a-local-password"}))
    monkeypatch.setenv("SSREFUSE_OPENCODE_SERVICE_CONFIG", str(path))
    assert opencode.service_password() == "a-local-password"


def test_the_username_is_fixed_because_the_other_shapes_answered_401():
    """Measured 2026-10-25: basic auth with user `opencode` answers 200, while
    no header, a bearer of the same password, and an empty username all answer
    401. The constant records which one was the measurement."""
    assert opencode.SERVICE_USER == "opencode"
