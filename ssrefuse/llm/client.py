"""Model client.

Two kinds of backend sit behind one interface here, and keeping both is the
point rather than a transitional state: a model is reached either by calling
a vendor's HTTP API directly, or by handing the prompt to an agent tool that
already holds the credentials.

* **chat-completions transport.** DeepSeek is the default and speaks the
  OpenAI chat-completions shape, so the same code reaches any endpoint that
  does: set SSREFUSE_LLM_BASE_URL and SSREFUSE_LLM_API_KEY_ENV to point it
  elsewhere, or use the ``openrouter`` provider. This is the transport that
  reports token usage and the chain of thought, so it is the one to prefer
  when the run has to account for what it spent.
* **opencode transport.** ``ssrefuse/llm/opencode.py`` posts the prompt to a
  locally running opencode server, which makes the upstream call on the
  account's own subscription. It costs nothing per call beyond that
  subscription, and it is the only way in from a machine whose direct
  requests to the gateway are refused by its proxy. It reports no token usage,
  so what it cannot measure is carried through as an absence rather than as a
  zero -- see ``usage_reported``.

Only ``requests`` is needed either way, which keeps the dependency list short
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
        "transport": "chat-completions",
        "base_url": "https://api.deepseek.com",
        "key_env": "DEEPSEEK_API_KEY",
        "models": ("deepseek-flash", "deepseek-v4-pro", "deepseek-v4-flash"),
        "default_model": "deepseek-flash",
        "supports_reasoning_effort": True,
    },
    "openrouter": {
        "transport": "chat-completions",
        "base_url": "https://openrouter.ai/api/v1",
        "key_env": "OPENROUTER_API_KEY",
        "models": (),            # ids are "vendor/model"; pass --model
        "default_model": os.environ.get("OPENROUTER_MODEL", ""),
        "supports_reasoning_effort": True,
    },
    "openai-compatible": {
        "transport": "chat-completions",
        "base_url": os.environ.get("SSREFUSE_LLM_BASE_URL", ""),
        "key_env": os.environ.get("SSREFUSE_LLM_API_KEY_ENV", "SSREFUSE_LLM_API_KEY"),
        "models": (),
        "default_model": os.environ.get("SSREFUSE_LLM_MODEL", ""),
        "supports_reasoning_effort": False,
    },
    # Reached through the opencode agent tool rather than over the vendor's
    # API, so there is no key to export: the running server holds the
    # account's OAuth token and refreshes it. Model ids are
    # `provider/model` as `opencode models` prints them, and the subscription
    # tier is part of the id -- `opencode-go/...` bills to an OpenCode Go
    # subscription while the `opencode/...` mirror of the same model is
    # pay-per-token and the `-free` tier has its own daily ceiling.
    "opencode": {
        "transport": "opencode",
        "base_url": "",          # discovered from the running server
        "key_env": "",           # the server holds the credential
        "models": (),
        "default_model": os.environ.get("SSREFUSE_OPENCODE_MODEL",
                                        "opencode-go/deepseek-v4.1-flash"),
        "supports_reasoning_effort": True,   # as a declared model variant
    },
    "mock": {"transport": "mock", "base_url": "", "key_env": "",
             "models": ("mock",), "default_model": "mock",
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
#         value of reasoning_effort. This is the real non-thinking arm.
#
# What the arm is called and what it did are two different facts, and until
# 2026-10-25 this file claimed the second one without checking it: the comment
# said the run asserted zero reasoning tokens at `off`, and nothing did. The
# only reader of the count printed it when it was non-zero, which is to say
# the single observation that would disprove the arm came out looking like an
# ordinary progress line. `thinking_control` below is that check, and it runs
# on every judge invocation.
REASONING_EFFORTS = ("none", "off", "low", "high", "max")

# What each arm claims about the thinking budget, as something testable. An
# ablation whose two arms both thought, or neither did, is one arm measured
# twice -- and that failure is invisible in the verdict columns, which is
# exactly why it needs its own line in the output rather than a reader's
# attention.
THINKING_CLAIM = {
    "off": "spent no reasoning tokens",
    "low": "spent reasoning tokens",
    "high": "spent reasoning tokens",
    "max": "spent reasoning tokens",
}


def thinking_control(effort: str, reasoning_tokens: int,
                     usage_reported: bool) -> dict:
    """Did the arm run at the budget its name claims?

    Three outcomes, and the third is the one worth having. A transport that
    reports no usage cannot answer this question, and `not_checked` says so
    instead of reading an absent count as a zero -- which would hand every
    agent-transport arm a passing `off` control it never earned.
    """
    if not usage_reported:
        return {"status": "not_checked", "effort": effort,
                "reasoning_tokens": None,
                "detail": "the transport reported no token usage, so the "
                          "thinking budget this arm actually ran at is "
                          "unknown. It is not zero."}
    claim = THINKING_CLAIM.get(effort)
    if claim is None:
        return {"status": "no_claim", "effort": effort,
                "reasoning_tokens": reasoning_tokens,
                "detail": "`none` sends no parameter and takes the provider's "
                          "default, so it claims nothing about the budget and "
                          "there is nothing here to contradict."}
    spent = reasoning_tokens > 0
    expected = effort != "off"
    if spent is expected:
        return {"status": "pass", "effort": effort,
                "reasoning_tokens": reasoning_tokens,
                "detail": f"arm `{effort}` {claim}: {reasoning_tokens} "
                          f"reasoning token(s)."}
    return {"status": "FAILED", "effort": effort,
            "reasoning_tokens": reasoning_tokens,
            "detail": (f"arm `{effort}` is supposed to have {claim} and spent "
                       f"{reasoning_tokens}. The arm did not run at the budget "
                       f"its name claims, so its rows describe some other "
                       f"measurement and cannot be compared with the rest.")}


# Where a token count hides, by vendor. The `openai-compatible` provider
# points at whatever endpoint someone configures, and a proxy in front of a
# model is free to hand back Anthropic's or Gemini's spelling, so reading only
# OpenAI's would lose the accounting without saying so.
#
# The lookup is written with explicit `is not None` checks rather than `or`
# chaining, which is the obvious way to write it and is wrong: a legitimate
# count of zero is falsy, so `a or b or 0` steps over a real zero and keeps
# looking. That matters precisely at `off`, where zero is the expected answer
# and the value the control is reading.
TOKEN_KEYS = {
    "input": ("prompt_tokens", "input_tokens", "promptTokenCount"),
    "output": ("completion_tokens", "output_tokens", "candidatesTokenCount"),
    "reasoning": ("reasoning_tokens", "thoughts_token_count",
                  "thoughtsTokenCount"),
}


def _first_present(mapping: dict, keys: tuple[str, ...]) -> int | None:
    for key in keys:
        value = mapping.get(key)
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                continue
    return None


def token_usage(usage: dict | None) -> dict:
    """Input, output and reasoning counts out of one provider's `usage` block.

    Returns ``found`` alongside the numbers so a caller can tell a block that
    said zero from a block that said nothing. Nested detail dicts are searched
    too, because that is where OpenAI-shaped endpoints put the reasoning
    count.
    """
    usage = usage or {}
    pools = [usage]
    for nested in ("completion_tokens_details", "output_tokens_details",
                   "usage_metadata", "token_usage"):
        value = usage.get(nested)
        if isinstance(value, dict):
            pools.append(value)
    out = {"found": False}
    for name, keys in TOKEN_KEYS.items():
        value = None
        for pool in pools:
            value = _first_present(pool, keys)
            if value is not None:
                break
        out[name] = value or 0
        if value is not None:
            out["found"] = True
    return out


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
    # False means the transport never told us what the call cost. That is a
    # different fact from "it cost nothing", and the two must not render the
    # same way in a cost table.
    usage_reported: bool = True

    @property
    def reasoning_tokens(self) -> int:
        """What the thinking cost, from the provider's own accounting."""
        return token_usage(self.usage)["reasoning"]


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
        # Answers, and how many of them came with no accounting attached.
        # A count rather than a flag: "47 answers, 47 without usage" and
        # "47 answers, 1 without usage" are different runs and a boolean
        # renders them identically. Cache hits count as answers, because a
        # fully-cached run has made no calls and must still be able to say
        # whether what it is serving was ever accounted for.
        self.answers = 0
        self.answers_missing_usage = 0
        self._opencode = None

    @property
    def is_mock(self) -> bool:
        return self.provider == "mock"

    @property
    def transport(self) -> str:
        return self.spec.get("transport", "chat-completions")

    @property
    def usage_reported(self) -> bool:
        """Did every answer this run served come with an accounting?

        Measured, not declared. `capabilities` says what the transport is able
        to report; this says what it did report. The project keeps that split
        everywhere else -- a label is a claim and the prober is the evidence --
        and a cost table has the same need.
        """
        return self.answers > 0 and self.answers_missing_usage == 0

    def _count_answer(self, completion: "Completion") -> "Completion":
        self.answers += 1
        if not completion.usage_reported:
            self.answers_missing_usage += 1
        return completion

    @property
    def capabilities(self) -> dict:
        """What this transport can and cannot tell us, as data.

        The reporting layer reads this rather than guessing from a zero, which
        is the difference between a table that says `n/a` and one that claims
        a run spent no tokens.
        """
        if self.transport == "opencode":
            from ssrefuse.llm.opencode import CAPABILITIES
            return dict(CAPABILITIES)
        return {"usage_reported": not self.is_mock,
                "reasoning_content_returned": bool(
                    self.spec.get("supports_reasoning_effort")),
                "temperature_settable": True,
                "json_mode": True}

    def _opencode_transport(self):
        if self._opencode is None:
            from ssrefuse.llm.opencode import OpencodeTransport
            # A generous floor on the timeout, and not an arbitrary one: a
            # call at effort=high was measured at roughly two minutes against
            # this corpus on 2026-10-25, which the 180s default would cut off
            # part way through. Waiting longer costs nothing here because the
            # budget is a subscription rather than tokens, while timing out
            # at 170 seconds of thinking throws the whole call away.
            self._opencode = OpencodeTransport(timeout=max(self.timeout, 600.0))
        return self._opencode

    def describe(self) -> dict:
        capabilities = self.capabilities
        reported = self.usage_reported and capabilities["usage_reported"]
        thinking = thinking_control(self.reasoning_effort, self.reasoning_tokens,
                                    reported)
        return {"provider": self.provider, "model": self.model,
                "transport": self.transport,
                "temperature": self.temperature, "is_mock": self.is_mock,
                "reasoning_effort": self.reasoning_effort,
                "reasoning_tokens": self.reasoning_tokens,
                "json_mode_refusals": self.json_mode_refusals,
                "calls": self.calls, "tokens_in": self.tokens_in,
                "tokens_out": self.tokens_out, "cache": self.cache.stats(),
                # The counters above are real only if something reported them.
                # This flag is what the report keys off; without it a run on a
                # transport that reports no usage is indistinguishable in the
                # results file from a run that was never made.
                "usage_reported": reported,
                "answers": self.answers,
                "answers_missing_usage": self.answers_missing_usage,
                "capabilities": capabilities,
                # The temperature asked for is not always the temperature used.
                # opencode's stateless endpoint takes no temperature, so the
                # number above is a request this run did not get to make.
                "temperature_sent": capabilities["temperature_settable"],
                "thinking_control": thinking}

    def check_ready(self) -> None:
        """Fail now, with the fix in the message, rather than mid-evaluation."""
        if self.is_mock:
            return
        if self.transport == "opencode":
            from ssrefuse.llm.opencode import OpencodeUnavailable
            try:
                # Resolving the model proves four things before a single
                # prompt is spent: the server is up, the password matches, the
                # account can reach this model, and the variant that carries
                # the thinking budget is one the model actually declares.
                self._opencode_transport().resolve(
                    self.model, self._opencode_variant())
            except OpencodeUnavailable as exc:
                raise LLMUnavailable(str(exc)) from exc
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

    def _opencode_variant(self) -> str | None:
        """The thinking budget as opencode spells it, or a refusal.

        ``off`` has no spelling here. The provider exposes thinking as a set
        of declared variants and none of them means "do not think", so the
        non-thinking arm cannot be run on this transport. Falling back to the
        model default would produce a column labelled ``off`` that was
        measured at whatever the default happens to be, which is the one
        outcome worth raising over.
        """
        from ssrefuse.llm.opencode import VARIANT_FOR_EFFORT
        if self.reasoning_effort not in VARIANT_FOR_EFFORT:
            raise LLMUnavailable(
                f"effort {self.reasoning_effort!r} cannot be expressed on the "
                f"opencode transport, which offers "
                f"{', '.join(k for k in VARIANT_FOR_EFFORT)}. There is no "
                f"variant that disables thinking, so the `off` arm needs a "
                f"provider that takes it as a request parameter "
                f"(--provider deepseek). `--effort none` here means the "
                f"model's own default, which is not the same measurement.")
        return VARIANT_FOR_EFFORT[self.reasoning_effort]

    def _complete_opencode(self, prompt: str, system: str, key: str) -> Completion:
        """One stateless generation through the local agent server.

        The system prompt is prepended rather than sent as its own message:
        the endpoint takes a single ``prompt`` string. That is a real
        difference from the chat-completions transport and it is why the two
        are not interchangeable for a prompt-sensitivity claim.
        """
        from ssrefuse.llm.opencode import OpencodeUnavailable
        variant = self._opencode_variant()
        text = (f"{system}\n\n{prompt}" if system else prompt)
        started = time.time()
        try:
            answer = self._opencode_transport().generate(text, self.model, variant)
        except OpencodeUnavailable as exc:
            raise LLMUnavailable(str(exc)) from exc
        latency = time.time() - started
        self.calls += 1
        self.cache.put(key, {"text": answer, "model": self.model,
                             "provider": self.provider, "usage": {},
                             "is_mock": False, "reasoning": "",
                             "json_mode_refused": False,
                             "usage_reported": False})
        return self._count_answer(
            Completion(text=answer, model=self.model, provider=self.provider,
                       usage={}, latency_s=latency, usage_reported=False))

    def complete(self, prompt: str, system: str = "", json_mode: bool = True) -> Completion:
        # The effort is part of the key: the same prompt at a different
        # thinking budget is a different measurement, and serving one from the
        # other's cache would quietly collapse the ablation into one column.
        key = cache_key(self.provider, self.model, prompt, self.temperature,
                        system + f"|effort={self.reasoning_effort}")
        hit = self.cache.get(key)
        if hit is not None:
            return self._count_answer(Completion(
                text=hit["text"], model=hit["model"],
                provider=hit["provider"], cached=True,
                usage=hit.get("usage", {}),
                is_mock=hit.get("is_mock", False),
                reasoning=hit.get("reasoning", ""),
                json_mode_refused=hit.get("json_mode_refused", False),
                usage_reported=hit.get("usage_reported", True)))
        if self.is_mock:
            # A mock answer has no usage because nothing was called. That is a
            # true zero rather than an unknown, but it is still not an
            # accounting, so it is counted as missing and the mock warning
            # elsewhere carries the interpretation.
            completion = Completion(text=_mock_answer(prompt), model="mock",
                                    provider="mock", is_mock=True,
                                    usage_reported=False)
            self.cache.put(key, {"text": completion.text, "model": "mock",
                                 "provider": "mock", "is_mock": True,
                                 "usage": {}, "usage_reported": False})
            return self._count_answer(completion)

        self.check_ready()
        if self.transport == "opencode":
            return self._complete_opencode(prompt, system, key)
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
            counts = token_usage(usage)
            self.calls += 1
            self.tokens_in += counts["input"]
            self.tokens_out += counts["output"]
            self.reasoning_tokens += counts["reasoning"]
            self.cache.put(key, {"text": text, "model": self.model,
                                 "provider": self.provider, "usage": usage,
                                 "is_mock": False, "reasoning": reasoning,
                                 "json_mode_refused": json_mode_refused,
                                 "usage_reported": counts["found"]})
            # `usage` absent from a 200 is a real case -- a proxy that strips
            # it, an endpoint that never sends it -- and it must not be read as
            # a free call. The flag follows the payload, not the provider name.
            return self._count_answer(Completion(
                text=text, model=self.model, provider=self.provider,
                usage=usage, latency_s=latency, reasoning=reasoning,
                json_mode_refused=json_mode_refused,
                usage_reported=counts["found"]))
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
