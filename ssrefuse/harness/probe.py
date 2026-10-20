"""Dynamic prober: fire every applicable payload at every labelled variant.

Verdicts are kept apart on purpose. "The guard blocked it", "the sink raised",
and "the request went out but nothing came back" are three different facts, and
collapsing them into a single "not vulnerable" column is how a bypass matrix
ends up overstating how well a filter works. The verdicts are:

  reached_internal  an internal canary marker came back, or the internal target
                    logged the hit -- the only verdict that counts as a bypass
  reached_not_disclosed
                    the request arrived at the internal service and the service
                    did not hand over its secret. Header-gated cloud metadata is
                    the case this exists for: the application's guard did not
                    stop the request, the cloud's own mitigation did, and
                    scoring that as either a bypass or a block would credit the
                    wrong defender
  oob_confirmed     the out-of-band canary logged a DNS query or HTTP hit
  reached_benign    the fetch succeeded against the allowlisted partner host;
                    this is the control outcome, never a finding
  blocked           the application itself refused the input, with its reason
  sink_error        the fetch was attempted and failed in the client library
  no_internal_contact
                    the application answered and nothing was refused, but no
                    internal target was reached; the evidence names whichever
                    host was contacted instead, so this is never read as a guard
                    holding when in fact the request simply went elsewhere
  not_applicable    the family has no value for this injection shape

Everything runs inside the sandbox namespace, which is created fresh for each
run. That is also what makes the usual stale-server problem impossible here: a
brand-new network namespace has no other process holding the lab port, so a
measurement cannot accidentally be taken against a server left over from an
earlier build.
"""
from __future__ import annotations

import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from ssrefuse import testbed_spec as spec
from ssrefuse.corpus import REPO_ROOT, Corpus, Variant
from ssrefuse.harness import payloads as payload_catalog

# Every service that counts as "inside". Kept as one set so that adding a
# service to the testbed and forgetting it here cannot turn a reached target
# into a quiet no_internal_contact.
INTERNAL_SERVICES = {
    "internal-admin", "internal-admin6", "metadata", "cgnat",
    "metadata-ecs", "metadata-alibaba", "intranet",
    "docker-api", "elasticsearch", "consul", "actuator",
    "redis", "memcached",
}
PUBLIC_SERVICES = {"public-site", "oob-http"}
RETRY_FAMILIES = {"B14_dns_rebinding": 6}   # time-of-check races need several tries


@dataclass
class Attempt:
    status: int | None = None
    blocked_reason: str = ""
    marker_in_body: str = ""
    body_head: str = ""
    log_rows: list[dict] = field(default_factory=list)
    dns_answers: list[str] = field(default_factory=list)
    error: str = ""


@dataclass
class Outcome:
    variant: str
    family: str
    payload: str
    kind: str
    expect: str
    verdict: str
    evidence: str
    attempts: list[Attempt] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "variant": self.variant, "family": self.family, "payload": self.payload,
            "kind": self.kind, "expect": self.expect, "verdict": self.verdict,
            "evidence": self.evidence,
            "attempts": [vars(a) for a in self.attempts],
        }


class LabProcess:
    """A lab application under test, started as a child process.

    stdout goes to a file rather than a pipe: the lab spawns its own children
    (the curl sink does), and a child that inherits a pipe keeps the write end
    open, so a reader waiting for the ready line could block forever.
    """

    def __init__(self, app, port: int, log_dir: Path, python: str | None = None):
        self.app = app
        self.port = port
        self.log_path = Path(log_dir) / f"lab-{app.name}-{port}.log"
        self.python = python or sys.executable
        self.proc: subprocess.Popen | None = None
        self.ready_line = ""

    def start(self, timeout: float = 25.0) -> dict:
        cmd = [arg.replace("{port}", str(self.port)) for arg in self.app.start]
        if cmd[0] == "python":
            cmd[0] = self.python
        elif not os.path.isabs(cmd[0]) and shutil.which(cmd[0]) is None:
            # Said plainly here rather than left as a FileNotFoundError from
            # Popen: an interpreter missing from the sandbox PATH is a setup
            # problem, and it must not be mistaken for a lab that failed to
            # start or, worse, for a run with one lab silently absent.
            raise RuntimeError(
                f"cannot start lab {self.app.name!r}: {cmd[0]!r} is not on PATH. "
                f"The {self.app.lang} lab needs it; install it or run "
                f"`ssrefuse probe --apps` with the labs that can run here.")
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        handle = open(self.log_path, "w")
        self.proc = subprocess.Popen(
            cmd, cwd=str(REPO_ROOT), stdout=handle, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=dict(os.environ, PYTHONUNBUFFERED="1", PYTHONPATH=str(REPO_ROOT)),
        )
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"lab exited early (code {self.proc.returncode}):\n"
                                   f"{self.log_path.read_text()[-1500:]}")
            text = self.log_path.read_text()
            for line in text.splitlines():
                if line.startswith(self.app.ready_marker):
                    self.ready_line = line.strip()
                    break
            if self.ready_line and self._port_open():
                return self._identity()
            time.sleep(0.1)
        raise RuntimeError(f"lab never printed {self.app.ready_marker!r} on port {self.port}:\n"
                           f"{self.log_path.read_text()[-1500:]}")

    def _port_open(self) -> bool:
        try:
            sock = socket.create_connection(("127.0.0.1", self.port), timeout=0.5)
            sock.close()
            return True
        except OSError:
            return False

    def _identity(self) -> dict:
        """Who actually holds the port, read from the socket table, not from a
        process name. The ready line is read back out of the running process so
        the build under test is reported by the code that is answering."""
        owner = "ss unavailable"
        try:
            out = subprocess.run(["ss", "-ltnpH", f"sport = :{self.port}"],
                                 capture_output=True, text=True, timeout=5).stdout
            found = re.search(r"pid=(\d+)", out)
            if found:
                owner = found.group(1)
                if self.proc and int(owner) != self.proc.pid:
                    raise AssertionError(
                        f"port {self.port} is held by pid {owner}, not by the lab we "
                        f"started (pid {self.proc.pid}); refusing to measure")
        except FileNotFoundError:
            pass
        return {"pid": self.proc.pid if self.proc else None, "port_owner_pid": owner,
                "ready_line": self.ready_line, "log": str(self.log_path),
                "command": " ".join(self.app.start)}

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


class LogWindow:
    """Reads the testbed access log and hands back only the rows a probe caused.

    Probes run one at a time, so a row written between the offset taken before
    the request and the offset taken after it belongs to that request.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.offset = self.path.stat().st_size if self.path.exists() else 0

    def mark(self) -> None:
        self.offset = self.path.stat().st_size if self.path.exists() else 0

    def rows_since(self) -> list[dict]:
        if not self.path.exists():
            return []
        with open(self.path) as handle:
            handle.seek(self.offset)
            chunk = handle.read()
        self.offset += len(chunk)
        rows = []
        for line in chunk.splitlines():
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    rows.append({"service": "unparsable", "raw": line[:200]})
        return rows


def _request(port: int, method: str, path: str, body: dict | None = None,
             timeout: float = 15.0) -> tuple[int, str]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        payload = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"} if payload else {}
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.read().decode("utf-8", "replace")
    finally:
        conn.close()


def _set_json_path(target: dict, dotted: str, value: str) -> None:
    keys = dotted.split(".")
    node = target
    for key in keys[:-1]:
        node = node.setdefault(key, {})
    node[keys[-1]] = value


def _build_steps(variant: Variant, value: str) -> list[dict]:
    """Normalise every entry shape into a list of request steps."""
    entry = variant.entry
    if "steps" in entry:
        steps = []
        for raw in entry["steps"]:
            step = dict(raw)
            step["value"] = value if step.get("inject") else None
            steps.append(step)
        return steps
    return [dict(entry, value=value)]


def _render_step(step: dict, value: str | None, captured: dict) -> tuple[str, str, dict | None]:
    method = step.get("method", "GET")
    path = step["path"].format(**captured)
    body = None
    inject = step.get("inject", "none")
    if inject == "query" and value is not None:
        joiner = "&" if "?" in path else "?"
        path = f"{path}{joiner}{urllib.parse.urlencode({step['param']: value})}"
    elif inject == "json" and value is not None:
        body = {}
        _set_json_path(body, step["json_path"], value)
    return method, path, body


def _classify(variant: Variant, payload, attempt: Attempt) -> tuple[str, str]:
    """Decide what a single attempt proved, in the order the evidence binds."""
    if attempt.error:
        return "sink_error", f"probe transport error: {attempt.error}"

    internal_hits = [row for row in attempt.log_rows
                     if row.get("service") in INTERNAL_SERVICES]
    oob_hits = [row for row in attempt.log_rows
                if row.get("service") in ("dns-oob", "oob-http")]

    if payload.expected_marker in spec.INTERNAL_MARKERS:
        if attempt.marker_in_body == payload.expected_marker:
            return "reached_internal", (
                f"canary {payload.expected_marker} present in the application's "
                f"response (HTTP {attempt.status})")
        if internal_hits:
            services = sorted({row["service"] for row in internal_hits})
            if not payload.discloses:
                # The family said in advance that the service withholds its
                # secret without a request header the attacker cannot set. The
                # request still arrived, so this is neither a bypass nor a
                # guard holding, and it gets its own verdict rather than being
                # rounded to whichever of the two is nearer.
                return "reached_not_disclosed", (
                    f"{', '.join(services)} logged {len(internal_hits)} request(s), "
                    f"and the service withheld {payload.expected_marker}: the "
                    f"application did not stop this, the service did")
            return "reached_internal", (
                f"no marker in body, but {', '.join(services)} logged "
                f"{len(internal_hits)} request(s) during this probe")
    if payload.expect == "oob" and oob_hits:
        kinds = sorted({row["service"] for row in oob_hits})
        return "oob_confirmed", f"out-of-band canary fired: {', '.join(kinds)}"
    if payload.expect == "benign":
        if attempt.marker_in_body == spec.MARKER_BENIGN:
            return "reached_benign", (
                f"control payload reached the allowlisted partner host "
                f"(HTTP {attempt.status})")
        # A blind variant discards the body, so the control has to be confirmed
        # the same way the attack is: by the target logging the request.
        if any(row.get("service") == "public-site" for row in attempt.log_rows):
            return "reached_benign", (
                "control payload reached the allowlisted partner host, confirmed "
                "by the partner's access log rather than by the response body")
        if attempt.blocked_reason:
            return "blocked", f"control payload was refused: {attempt.blocked_reason}"

    if attempt.blocked_reason:
        return "blocked", f"application refused the input: {attempt.blocked_reason}"
    if attempt.status and attempt.status >= 500:
        return "sink_error", f"application returned HTTP {attempt.status}"
    if internal_hits:
        services = sorted({row["service"] for row in internal_hits})
        return "reached_internal", (
            f"unexpected internal contact logged by {', '.join(services)}")

    contacted = sorted({row["service"] for row in attempt.log_rows
                        if row.get("service") not in ("dns", "dns-oob")})
    if contacted:
        return "no_internal_contact", (
            f"the fetch happened and reached {', '.join(contacted)}, which is not "
            f"an internal target (HTTP {attempt.status})")
    return "no_internal_contact", (
        f"HTTP {attempt.status}, nothing was refused, and no target logged a "
        f"request: the fetch did not complete (body head: {attempt.body_head!r})")


class Prober:
    def __init__(self, corpus: Corpus, access_log: str | Path, log_dir: str | Path):
        self.corpus = corpus
        self.window = LogWindow(access_log)
        self.log_dir = Path(log_dir)

    def _attempt(self, variant: Variant, payload, port: int) -> Attempt:
        attempt = Attempt()
        self.window.mark()
        captured: dict[str, str] = {}
        status, body = None, ""
        try:
            for step in _build_steps(variant, payload.value):
                method, path, json_body = _render_step(step, step.get("value"), captured)
                status, body = _request(port, method, path, json_body)
                if step.get("capture"):
                    try:
                        parsed = json.loads(body)
                    except json.JSONDecodeError:
                        parsed = {}
                    for name, key in step["capture"].items():
                        captured[name] = str(parsed.get(key, ""))
        except Exception as exc:  # noqa: BLE001 - recorded as sink_error evidence
            attempt.error = f"{type(exc).__name__}: {exc}"

        attempt.status = status
        attempt.body_head = (body or "")[:180].replace("\n", " ")
        attempt.log_rows = self.window.rows_since()
        attempt.dns_answers = [f"{r.get('qname')}->{r.get('answer')}"
                               for r in attempt.log_rows if r.get("service") == "dns"]
        for marker in payload_catalog.EXPECT_MARKERS.values():
            if marker in (body or ""):
                attempt.marker_in_body = marker
                break
        if body:
            try:
                parsed = json.loads(body)
                if isinstance(parsed, dict) and parsed.get("blocked"):
                    attempt.blocked_reason = str(parsed["blocked"])
            except json.JSONDecodeError:
                pass
        return attempt

    def probe_variant(self, variant: Variant, port: int) -> list[Outcome]:
        kind = variant.payload_kind
        outcomes: list[Outcome] = []
        applicable = set(payload_catalog.applicable_families(kind))
        for family in payload_catalog.FAMILIES:
            if family.id not in applicable:
                outcomes.append(Outcome(
                    variant.id, family.id, "", kind, "",
                    "not_applicable",
                    f"family has no value for injection shape {kind!r}"))
        for payload in payload_catalog.payloads_for_kind(kind):
            tries = RETRY_FAMILIES.get(payload.family, 1)
            attempts: list[Attempt] = []
            verdict, evidence = "no_internal_contact", "no attempt recorded"
            for _ in range(tries):
                attempt = self._attempt(variant, payload, port)
                attempts.append(attempt)
                verdict, evidence = _classify(variant, payload, attempt)
                if verdict in ("reached_internal", "oob_confirmed", "reached_benign"):
                    break
            if tries > 1:
                evidence += f" [{len(attempts)} of {tries} attempts used]"
            outcomes.append(Outcome(variant.id, payload.family, payload.value, payload.kind,
                                    payload.expect, verdict, evidence, attempts))
        return outcomes

    def run_app(self, app_name: str, port: int, python: str | None = None) -> dict:
        app = self.corpus.apps[app_name]
        lab = LabProcess(app, port, self.log_dir, python=python)
        identity = lab.start()
        try:
            outcomes: list[Outcome] = []
            for variant in self.corpus.for_app(app_name):
                outcomes += self.probe_variant(variant, port)
        finally:
            lab.stop()
        return {"app": app_name, "lab": identity,
                "outcomes": [o.as_dict() for o in outcomes]}
