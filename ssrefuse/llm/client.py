"""Model client.

DeepSeek is the default and speaks the OpenAI chat-completions shape, so the
same code reaches any endpoint that does: set SSREFUSE_LLM_BASE_URL and
SSREFUSE_LLM_API_KEY_ENV to point it elsewhere. Only ``requests`` is needed,
which keeps the dependency list short enough that the evaluation runs on a clean
machine without a vendor SDK.

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

PROVIDERS = {
    "deepseek": {
        "base_url": "https://api.deepseek.com",
        "key_env": "DEEPSEEK_API_KEY",
        "models": ("deepseek-chat", "deepseek-reasoner"),
        "default_model": "deepseek-chat",
    },
    "openai-compatible": {
        "base_url": os.environ.get("SSREFUSE_LLM_BASE_URL", ""),
        "key_env": os.environ.get("SSREFUSE_LLM_API_KEY_ENV", "SSREFUSE_LLM_API_KEY"),
        "models": (),
        "default_model": os.environ.get("SSREFUSE_LLM_MODEL", ""),
    },
    "mock": {"base_url": "", "key_env": "", "models": ("mock",), "default_model": "mock"},
}


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


class LLMClient:
    def __init__(self, provider: str = "deepseek", model: str | None = None,
                 temperature: float = 0.0, cache: ResponseCache | None = None,
                 timeout: float = 180.0, max_retries: int = 3):
        if provider not in PROVIDERS:
            raise LLMUnavailable(f"unknown provider {provider!r}; "
                                 f"known: {', '.join(sorted(PROVIDERS))}")
        self.provider = provider
        self.spec = PROVIDERS[provider]
        self.model = model or self.spec["default_model"]
        self.temperature = temperature
        self.cache = cache if cache is not None else ResponseCache()
        self.timeout = timeout
        self.max_retries = max_retries
        self.calls = 0
        self.tokens_in = 0
        self.tokens_out = 0

    @property
    def is_mock(self) -> bool:
        return self.provider == "mock"

    def describe(self) -> dict:
        return {"provider": self.provider, "model": self.model,
                "temperature": self.temperature, "is_mock": self.is_mock,
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
        key = cache_key(self.provider, self.model, prompt, self.temperature, system)
        hit = self.cache.get(key)
        if hit is not None:
            return Completion(text=hit["text"], model=hit["model"],
                              provider=hit["provider"], cached=True,
                              usage=hit.get("usage", {}),
                              is_mock=hit.get("is_mock", False))
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

        url = self.spec["base_url"].rstrip("/") + "/chat/completions"
        headers = {"Authorization": f"Bearer {os.environ[self.spec['key_env']]}",
                   "Content-Type": "application/json"}

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
                raise LLMUnavailable(f"HTTP {response.status_code}: {response.text[:400]}")

            payload = response.json()
            text = payload["choices"][0]["message"]["content"]
            usage = payload.get("usage", {})
            self.calls += 1
            self.tokens_in += usage.get("prompt_tokens", 0)
            self.tokens_out += usage.get("completion_tokens", 0)
            self.cache.put(key, {"text": text, "model": self.model,
                                 "provider": self.provider, "usage": usage,
                                 "is_mock": False})
            return Completion(text=text, model=self.model, provider=self.provider,
                              usage=usage, latency_s=latency)
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
