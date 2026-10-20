"""Model client.

DeepSeek is the default and speaks the OpenAI chat-completions shape, so the
same code reaches any endpoint that does: set SSREFUSE_LLM_BASE_URL and
SSREFUSE_LLM_API_KEY_ENV to point it elsewhere, or use the ``openrouter``
provider. Only ``requests`` is needed, which keeps the dependency list short
enough that the evaluation runs on a clean machine without a vendor SDK.

Two things about reasoning models shape this file, and both were read off the
provider's own documentation rather than assumed:

* **Thinking is a request parameter, not a model name.** It used to be a model
  name -- ``deepseek-chat`` for non-thinking and ``deepseek-reasoner`` for
  thinking -- and those names were scheduled for retirement. The ablation is
  therefore ``reasoning_effort`` over one model rather than two model names,
  which is the better experiment anyway: the model is held fixed and only the
  thinking budget moves, so a difference in the numbers has one cause.
* **The chain of thought comes back in its own field.** ``reasoning_content``
  sits beside ``content`` in the message. It is recorded, and its token count
  with it, because "the reasoning tier scored higher" and "the reasoning tier
  scored higher and cost nine times as much" are different findings.

JSON mode and thinking mode are not documented as compatible, so the client
tries ``response_format`` and falls back once without it, recording that it
did. The judge already recovers a JSON object from surrounding prose, so the
fallback degrades parsing rather than the run -- but silently degrading is how
a pipeline reports a number it did not earn, hence the record.

The mock provider exists so the plumbing can be tested without a key. It marks
every response it produces, and the judge carries that mark into its output, so
a mock answer can never be mistaken for a measurement.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field

import requests

from ssrefuse.llm.cache import ResponseCache, cache_key

# Model ids verified against the provider changelog on 2026-10-20, because the
# previous set was already stale: `deepseek-chat` and `deepseek-reasoner` were
# scheduled for retirement on 2026-07-24, and while they lived they selected
# the non-thinking and thinking modes of V4-Flash. `reasoning_effort` does that
# job now. Re-check before a submission: a model id is a version, and this
# project does not trust a version it did not look up.
PROVIDERS = {
    "deepseek": {
        "base_url": "https://api.deepseek.com",
        "key_env": "DEEPSEEK_API_KEY",
        "models": ("deepseek-flash", "deepseek-v4-pro", "deepseek-v4-flash"),
        "default_model": "deepseek-flash",
        "supports_reasoning_effort": True,
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "key_env": "OPENROUTER_API_KEY",
        "models": (),            # ids are "vendor/model"; pass --model
        "default_model": os.environ.get("OPENROUTER_MODEL", ""),
        "supports_reasoning_effort": True,
    },
    "openai-compatible": {
        "base_url": os.environ.get("SSREFUSE_LLM_BASE_URL", ""),
        "key_env": os.environ.get("SSREFUSE_LLM_API_KEY_ENV", "SSREFUSE_LLM_API_KEY"),
        "models": (),
        "default_model": os.environ.get("SSREFUSE_LLM_MODEL", ""),
        "supports_reasoning_effort": False,
    },
    "mock": {"base_url": "", "key_env": "", "models": ("mock",), "default_model": "mock",
             "supports_reasoning_effort": False},
}

# `low`, `high` and `max` are the provider's own values. The other two are this
# project's, and the difference between them is the one that was nearly got
# wrong:
#
#   none  send no thinking parameter at all -- the provider's default. MEASURED
#         2026-10-20: the default is thinking ON. A single call at `none`
#         returned 143 reasoning tokens, so `none` is not a non-thinking arm
#         and an ablation of none-against-high compares the default with
#         itself.
#   off   explicitly disable thinking, which is a separate field rather than a
#         value of reasoning_effort. This is the real non-thinking arm, and
#         the run asserts it by checking that it spent zero reasoning tokens.
REASONING_EFFORTS = ("none", "off", "low", "high", "max")


class LLMUnavailable(RuntimeError):
    pass


@dataclass
class Completion:
    text: str
    model: str
    provider: str
    cached: bool = False
    usage: dict = field(default_factory=dict)
    latency_s: float = 0.0
    is_mock: bool = False
    reasoning: str = ""          # the model's own chain of thought, if returned
    json_mode_refused: bool = False   # the endpoint rejected response_format

    @property
    def reasoning_tokens(self) -> int:
        """What the thinking cost, from the provider's own accounting."""
        usage = self.usage or {}
        detail = usage.get("completion_tokens_details") or {}
        return int(detail.get("reasoning_tokens") or usage.get("reasoning_tokens") or 0)


class LLMClient:
    def __init__(self, provider: str = "deepseek", model: str | None = None,
                 temperature: float = 0.0, cache: ResponseCache | None = None,
                 timeout: float = 180.0, max_retries: int = 3,
                 reasoning_effort: str = "none"):
        if provider not in PROVIDERS:
            raise LLMUnavailable(f"unknown provider {provider!r}; "
                                 f"known: {', '.join(sorted(PROVIDERS))}")
        if reasoning_effort not in REASONING_EFFORTS:
            raise LLMUnavailable(f"unknown reasoning effort {reasoning_effort!r}; "
                                 f"known: {', '.join(REASONING_EFFORTS)}")
        self.provider = provider
        self.spec = PROVIDERS[provider]
        self.model = model or self.spec["default_model"]
        self.temperature = temperature
        self.reasoning_effort = reasoning_effort
        self.cache = cache if cache is not None else ResponseCache()
        self.timeout = timeout
        self.max_retries = max_retries
        self.calls = 0
        self.tokens_in = 0
        self.tokens_out = 0
        self.reasoning_tokens = 0
        self.json_mode_refusals = 0

    @property
    def is_mock(self) -> bool:
        return self.provider == "mock"

    def describe(self) -> dict:
        return {"provider": self.provider, "model": self.model,
                "temperature": self.temperature, "is_mock": self.is_mock,
                "reasoning_effort": self.reasoning_effort,
                "reasoning_tokens": self.reasoning_tokens,
                "json_mode_refusals": self.json_mode_refusals,
                "calls": self.calls, "tokens_in": self.tokens_in,
                "tokens_out": self.tokens_out, "cache": self.cache.stats()}

    def check_ready(self) -> None:
        """Fail now, with the fix in the message, rather than mid-evaluation."""
        if self.is_mock:
            return
        if not self.spec["base_url"]:
            raise LLMUnavailable(
                f"provider {self.provider!r} has no base URL; set "
                f"SSREFUSE_LLM_BASE_URL")
        if not self.model:
            raise LLMUnavailable(f"provider {self.provider!r} has no model; "
                                 f"pass --model or set SSREFUSE_LLM_MODEL")
        if not os.environ.get(self.spec["key_env"]):
            raise LLMUnavailable(
                f"{self.spec['key_env']} is not set, so no request can be made. "
                f"Export the key, or pass --provider mock to exercise the "
                f"pipeline without a model (mock answers are labelled as such "
                f"and are not results).")

    def complete(self, prompt: str, system: str = "", json_mode: bool = True) -> Completion:
        # The effort is part of the key: the same prompt at a different
        # thinking budget is a different measurement, and serving one from the
        # other's cache would quietly collapse the ablation into one column.
        key = cache_key(self.provider, self.model, prompt, self.temperature,
                        system + f"|effort={self.reasoning_effort}")
        hit = self.cache.get(key)
        if hit is not None:
            return Completion(text=hit["text"], model=hit["model"],
                              provider=hit["provider"], cached=True,
                              usage=hit.get("usage", {}),
                              is_mock=hit.get("is_mock", False),
                              reasoning=hit.get("reasoning", ""),
                              json_mode_refused=hit.get("json_mode_refused", False))
        if self.is_mock:
            completion = Completion(text=_mock_answer(prompt), model="mock",
                                    provider="mock", is_mock=True)
            self.cache.put(key, {"text": completion.text, "model": "mock",
                                 "provider": "mock", "is_mock": True, "usage": {}})
            return completion

        self.check_ready()
        messages = ([{"role": "system", "content": system}] if system else [])
        messages.append({"role": "user", "content": prompt})
        body = {"model": self.model, "messages": messages,
                "temperature": self.temperature, "stream": False}
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        if self.spec.get("supports_reasoning_effort"):
            if self.reasoning_effort == "off":
                # Disabling thinking is its own field; reasoning_effort has no
                # value that means "do not think".
                body["thinking"] = {"type": "disabled"}
            elif self.reasoning_effort != "none":
                body["reasoning_effort"] = self.reasoning_effort

        url = self.spec["base_url"].rstrip("/") + "/chat/completions"
        headers = {"Authorization": f"Bearer {os.environ[self.spec['key_env']]}",
                   "Content-Type": "application/json"}

        json_mode_refused = False
        last_error = ""
        for attempt in range(self.max_retries):
            started = time.time()
            try:
                response = requests.post(url, headers=headers, json=body,
                                         timeout=self.timeout)
            except requests.RequestException as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                time.sleep(2 ** attempt)
                continue
            latency = time.time() - started
            if response.status_code in (429, 500, 502, 503, 504):
                last_error = f"HTTP {response.status_code}: {response.text[:200]}"
                time.sleep(2 ** attempt)
                continue
            if response.status_code != 200:
                # Thinking mode and JSON mode are not documented as compatible.
                # Drop response_format once and try again rather than failing
                # the run, but record it: the judge can recover a JSON object
                # from prose, and a parse that had to work harder is a fact
                # about the run that belongs in the report.
                refusal = ("response_format" in response.text
                           or "json_object" in response.text)
                if refusal and "response_format" in body:
                    body.pop("response_format")
                    json_mode_refused = True
                    self.json_mode_refusals += 1
                    last_error = f"HTTP {response.status_code} on json mode, retrying without"
                    continue
                raise LLMUnavailable(f"HTTP {response.status_code}: {response.text[:400]}")

            payload = response.json()
            message = payload["choices"][0]["message"]
            text = message.get("content") or ""
            # The chain of thought arrives beside the answer, not inside it.
            reasoning = message.get("reasoning_content") or message.get("reasoning") or ""
            usage = payload.get("usage", {})
            if not text and reasoning:
                # A model that spent its whole budget thinking and returned no
                # answer is a failed call, not an empty verdict.
                last_error = ("the model returned reasoning and no content "
                              f"({len(reasoning)} characters of it)")
                continue
            detail = usage.get("completion_tokens_details") or {}
            self.calls += 1
            self.tokens_in += usage.get("prompt_tokens", 0)
            self.tokens_out += usage.get("completion_tokens", 0)
            self.reasoning_tokens += int(detail.get("reasoning_tokens")
                                         or usage.get("reasoning_tokens") or 0)
            self.cache.put(key, {"text": text, "model": self.model,
                                 "provider": self.provider, "usage": usage,
                                 "is_mock": False, "reasoning": reasoning,
                                 "json_mode_refused": json_mode_refused})
            return Completion(text=text, model=self.model, provider=self.provider,
                              usage=usage, latency_s=latency, reasoning=reasoning,
                              json_mode_refused=json_mode_refused)
        raise LLMUnavailable(f"{self.max_retries} attempts failed; last: {last_error}")


def _mock_answer(prompt: str) -> str:
    """A fixed, obviously-synthetic answer shaped like the real schema."""
    return json.dumps({
        "sink_call": "unknown (mock provider)",
        "destination_expression": "unknown (mock provider)",
        "source_chain": [],
        "validated_expression": None,
        "same_value_validated_and_fetched": None,
        "guard_survives": {"redirect": None, "second_resolution": None,
                           "address_spelling": None, "authority_confusion": None,
                           "percent_decoding": None},
        "verdict": "needs_dynamic_test",
        "confidence": 0.0,
        "bypass_families": [],
        "reasoning": "Mock provider: no model was called. This is not a result.",
        "unknowns": ["everything: no model was called"],
    })
