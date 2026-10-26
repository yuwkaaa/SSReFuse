"""Transport for the locally running opencode server.

The reason this file exists rather than another entry in the provider table is
that opencode is not reachable as a chat-completions URL from this process.
Its model gateway sits behind a proxy that answers an ordinary HTTP client
with ``403 error code: 1010`` -- a client-signature rejection, not an
authentication failure, and both a valid token and a deliberately invalid one
get the same 403, so that response says nothing about credentials. The
sanctioned client is opencode itself, which already holds the account's OAuth
token and refreshes it. So the request goes to opencode and opencode makes the
upstream call.

What that buys and what it costs, because the second half is what a reader of
the results needs:

* The account's subscription is the budget. ``opencode-go/deepseek-v4.1-flash``
  answers; the pay-per-token ``opencode/*`` mirror of the same model returns
  ``Insufficient account funds`` and the ``-free`` tier returns
  ``Free usage limit reached``. Those are terminal, not transient, so they are
  raised rather than retried -- a retry loop against a spent budget only turns
  one clear error into four.
* Thinking is a *declared model variant* here (``low``, ``high``, ``max``)
  rather than a free-form request parameter, and the server validates it: an
  undeclared variant is rejected with HTTP 400 rather than silently ignored,
  which is what makes ``--effort high`` worth trusting on this transport.
  There is no variant that turns thinking off, so the ``off`` arm is not
  available here and asking for it raises instead of quietly degrading to the
  provider default.
* The endpoint returns ``{"data": {"text": ...}}`` and nothing else. No token
  usage, no ``reasoning_content``, no temperature, no JSON mode. Those are not
  zeros, they are absences, and ``CAPABILITIES`` below is what the client
  carries into the results payload so the report prints ``n/a`` instead of a
  number nobody measured.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import requests

# The server is local and its password sits in a file next to its config. The
# username is fixed: basic auth with user `opencode` and this password answers
# 200, while no header, a bearer of the same password, and basic auth with an
# empty username all answer 401 -- measured 2026-10-25, which is what makes
# this the right scheme rather than the first one that happened to work.
SERVICE_USER = "opencode"
GENERATE_PATH = "/api/experimental/generate"

# The thinking budget, as this transport spells it. `none` means "send no
# variant and take whatever the model's own default is" and is deliberately
# not mapped to `low`: collapsing those two would hand the provider's default
# to the ablation under a name that claims to describe it.
VARIANT_FOR_EFFORT = {"none": None, "low": "low", "high": "high", "max": "max"}

# What the transport cannot report. Written down rather than left to an empty
# dict, because a reporting layer that sees no usage has to be able to tell
# "this run spent zero tokens" from "this run never learned what it spent".
CAPABILITIES = {
    "usage_reported": False,
    "reasoning_content_returned": False,
    "temperature_settable": False,
    "json_mode": False,
}

# Phrases that mean the budget is gone. Retrying these is pointless and the
# retry only buries the message that says what to do about it.
TERMINAL_UPSTREAM = ("insufficient account funds", "free usage limit reached",
                     "usage limit reached", "quota")


class OpencodeUnavailable(RuntimeError):
    """Raised with the fix in the message, never swallowed into a default."""


def service_config_path() -> Path:
    override = os.environ.get("SSREFUSE_OPENCODE_SERVICE_CONFIG")
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME") or "~/.config"
    return Path(base).expanduser() / "opencode" / "service.json"


def service_password(path: Path | None = None) -> str:
    path = path or service_config_path()
    if not path.exists():
        raise OpencodeUnavailable(
            f"no opencode service config at {path}. Start the server with "
            f"`opencode service start`, or point "
            f"SSREFUSE_OPENCODE_SERVICE_CONFIG at the file.")
    try:
        password = json.loads(path.read_text()).get("password")
    except json.JSONDecodeError as exc:
        raise OpencodeUnavailable(f"{path} is not valid JSON: {exc}") from exc
    if not password:
        raise OpencodeUnavailable(f"{path} has no `password` field")
    return password


def discover_server(timeout: float = 20.0) -> str:
    """Where the background server is listening.

    An explicit address wins, as everywhere else in this project. Otherwise
    ask opencode, because the port is assigned at startup and hard-coding the
    one seen today is how a measurement silently moves to a server that is not
    running.
    """
    explicit = os.environ.get("SSREFUSE_OPENCODE_SERVER")
    if explicit:
        return explicit.rstrip("/")
    try:
        done = subprocess.run(["opencode", "service", "status"],
                              capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        raise OpencodeUnavailable(
            "`opencode` is not on PATH, so the server address cannot be "
            "discovered. Install it, or set SSREFUSE_OPENCODE_SERVER to the "
            "address of a running one.") from exc
    except subprocess.TimeoutExpired as exc:
        raise OpencodeUnavailable(
            f"`opencode service status` did not answer within {timeout}s") from exc
    url = done.stdout.strip().splitlines()[-1].strip() if done.stdout.strip() else ""
    if not url.startswith("http"):
        raise OpencodeUnavailable(
            "`opencode service status` did not print a server address "
            f"(stdout {done.stdout.strip()!r}, stderr "
            f"{done.stderr.strip()[:200]!r}). Start it with "
            f"`opencode service start`.")
    return url.rstrip("/")


def split_model_ref(ref: str) -> tuple[str, str]:
    """``provider/model`` into its two halves.

    A `#variant` suffix is rejected rather than honoured. opencode's own CLI
    accepts `provider/model#variant`, but the thinking budget is this
    project's ablation axis and it already has a flag. Two ways to set one
    axis is how an arm ends up labelled with a budget it did not run at.
    """
    if "#" in ref:
        raise OpencodeUnavailable(
            f"model {ref!r} carries a `#variant` suffix. The thinking budget "
            f"is set with --effort on this project, so that it appears in the "
            f"arm name and in the cache key; pass --model "
            f"{ref.split('#', 1)[0]!r} --effort {ref.split('#', 1)[1]}.")
    if "/" not in ref:
        raise OpencodeUnavailable(
            f"model {ref!r} needs to be `provider/model`, for example "
            f"`opencode-go/deepseek-v4.1-flash`. Run `opencode models` for "
            f"the list.")
    provider_id, model_id = ref.split("/", 1)
    if not provider_id or not model_id:
        raise OpencodeUnavailable(f"model {ref!r} is not a `provider/model` pair")
    return provider_id, model_id


class OpencodeTransport:
    def __init__(self, server: str | None = None, timeout: float = 300.0,
                 password: str | None = None):
        self.server = (server or "").rstrip("/") or discover_server()
        self.timeout = timeout
        self._password = password
        self._models: list[dict] | None = None

    @property
    def auth(self) -> tuple[str, str]:
        if self._password is None:
            self._password = service_password()
        return (SERVICE_USER, self._password)

    def _request(self, method: str, path: str, body: dict | None = None):
        url = self.server + path
        try:
            response = requests.request(method, url, auth=self.auth, json=body,
                                        timeout=self.timeout)
        except requests.RequestException as exc:
            raise OpencodeUnavailable(
                f"{method} {url} failed: {type(exc).__name__}: {exc}. Is the "
                f"server up? `opencode service status`") from exc
        if response.status_code == 401:
            raise OpencodeUnavailable(
                f"{url} answered 401. The service password in "
                f"{service_config_path()} does not match the running server; "
                f"`opencode service restart` rewrites both.")
        return response

    def info(self) -> dict:
        response = self._request("GET", "/api/info")
        if response.status_code != 200:
            raise OpencodeUnavailable(
                f"GET /api/info answered {response.status_code}: "
                f"{response.text[:200]}")
        return response.json()

    def models(self, refresh: bool = False) -> list[dict]:
        if self._models is None or refresh:
            response = self._request("GET", "/api/model")
            if response.status_code != 200:
                raise OpencodeUnavailable(
                    f"GET /api/model answered {response.status_code}: "
                    f"{response.text[:200]}")
            self._models = response.json().get("data", [])
        return self._models

    def resolve(self, ref: str, variant: str | None = None) -> dict:
        """Find the model and prove the variant exists, before any call is made.

        This is the readiness check, and it is a real one: a model id that the
        account cannot reach and a variant the model does not declare are both
        findable here, for free, instead of two minutes into a run.
        """
        provider_id, model_id = split_model_ref(ref)
        entry = next((m for m in self.models()
                      if m.get("providerID") == provider_id
                      and m.get("modelID", m.get("id")) == model_id), None)
        if entry is None:
            available = sorted(f"{m.get('providerID')}/{m.get('modelID', m.get('id'))}"
                               for m in self.models())
            raise OpencodeUnavailable(
                f"opencode does not offer {ref!r}. {len(available)} model(s) "
                f"available; the deepseek ones are: "
                f"{', '.join(m for m in available if 'deepseek' in m) or 'none'}")
        if entry.get("enabled") is False or entry.get("status") not in (None, "active"):
            raise OpencodeUnavailable(
                f"{ref} is present but not usable (status "
                f"{entry.get('status')!r}, enabled {entry.get('enabled')!r})")
        if variant is not None:
            declared = [v.get("id") for v in entry.get("variants") or []]
            if variant not in declared:
                raise OpencodeUnavailable(
                    f"{ref} does not declare a {variant!r} variant; it has "
                    f"{declared or 'none'}. Use --effort none to take the "
                    f"model's own default.")
        return entry

    def generate(self, prompt: str, ref: str, variant: str | None = None) -> str:
        """One stateless generation. Returns the model's answer text.

        Stateless matters for the measurement: no session, no agent prompt and
        no tools in front of the model, so what is scored is the project's own
        prompt rather than the prompt plus whatever an agent wraps around it.
        """
        provider_id, model_id = split_model_ref(ref)
        model: dict = {"providerID": provider_id, "id": model_id}
        if variant is not None:
            model["variant"] = variant
        response = self._request("POST", GENERATE_PATH,
                                 {"prompt": prompt, "model": model})
        if response.status_code == 200:
            text = (response.json().get("data") or {}).get("text") or ""
            if not text:
                raise OpencodeUnavailable(
                    f"{GENERATE_PATH} answered 200 with no text: "
                    f"{response.text[:200]}")
            return text
        detail = response.text[:400]
        if response.status_code == 503 and any(p in detail.lower()
                                               for p in TERMINAL_UPSTREAM):
            raise OpencodeUnavailable(
                f"the account's budget for {ref} is spent, so no measurement "
                f"is possible on this model: {detail}")
        raise OpencodeUnavailable(f"HTTP {response.status_code} from "
                                  f"{GENERATE_PATH}: {detail}")
