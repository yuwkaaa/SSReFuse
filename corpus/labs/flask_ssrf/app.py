"""SSReFuse lab application (Python / Flask).

A deliberately vulnerable image-and-link preview service, in the shape real
applications take: one URL-fetching feature reached through several routes, each
with a different guard. Every route is bracketed by ``@ssrefuse:begin/end``
markers so the corpus loader can attribute a static-analysis finding to a
labelled variant without hardcoding line numbers.

The app is standalone on purpose -- it imports nothing from the ssrefuse package
so that static analysers see ordinary application code.

Testbed facts the guards are written against:
  public.ssrefuse.test  -> 192.88.99.10     the partner host this app trusts
  internal.ssrefuse.test-> 127.0.0.1        internal admin service, port 19001
  metadata.ssrefuse.test-> 169.254.169.254  fake cloud metadata
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
import sys
import urllib.parse
import urllib.request

import httpx
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

ALLOWED_HOST = "public.ssrefuse.test"
ALLOWED_ORIGIN = "http://public.ssrefuse.test"
BLOCKED_SUBSTRINGS = ["127.0.0.1", "localhost", "169.254.169.254"]
BLOCKED_HOSTS = {"127.0.0.1", "localhost", "169.254.169.254", "0.0.0.0"}
TIMEOUT = 4

# Pending preview jobs, written by one route and consumed by another. The second
# read is what makes the stored variant a second-order flow.
PREVIEW_QUEUE: dict[str, dict] = {}


def _ok(body: str, **extra):
    return jsonify({"ok": True, "body": body[:2000], **extra})


def _blocked(reason: str):
    return jsonify({"ok": False, "blocked": reason}), 403


# ---------------------------------------------------------------------------
# No guard at all
# ---------------------------------------------------------------------------

# @ssrefuse:begin py-001
@app.get("/preview/direct")
def preview_direct():
    """Textbook SSRF: the request parameter is the request target."""
    url = request.args.get("url", "")
    resp = requests.get(url, timeout=TIMEOUT)
    return _ok(resp.text, status=resp.status_code)
# @ssrefuse:end py-001


# @ssrefuse:begin py-002
@app.get("/preview/blind")
def preview_blind():
    """Same sink, but the response never reaches the caller.

    Only the fact that a fetch happened is observable, so this variant can only
    be confirmed through the target's own access log or a DNS callback.
    """
    url = request.args.get("url", "")
    try:
        requests.get(url, timeout=TIMEOUT)
    except Exception:
        pass
    return jsonify({"ok": True, "queued": True})
# @ssrefuse:end py-002


# @ssrefuse:begin shared.fetch_remote
def _fetch_remote(target: str) -> requests.Response:
    """Shared fetch helper: the hop that makes the flow interprocedural.

    This is where a static finding for py-003 and py-004 lands, since the sink
    lives here and not in either route. The region is marked shared so the
    evaluator can attribute it to both callers instead of discarding it.
    """
    return requests.get(target, timeout=TIMEOUT)
# @ssrefuse:end shared.fetch_remote


def _unwrap(payload: dict) -> str:
    return payload.get("source", {}).get("href", "")


# @ssrefuse:begin py-003
@app.get("/preview/helper")
def preview_helper():
    """Taint crosses a function boundary before reaching the sink."""
    url = request.args.get("url", "")
    resp = _fetch_remote(url)
    return _ok(resp.text, status=resp.status_code)
# @ssrefuse:end py-003


# @ssrefuse:begin py-004
@app.post("/preview/json")
def preview_json():
    """Taint arrives nested inside a JSON body and is read back out of a dict."""
    payload = request.get_json(silent=True) or {}
    url = _unwrap(payload)
    resp = _fetch_remote(url)
    return _ok(resp.text, status=resp.status_code)
# @ssrefuse:end py-004


# @ssrefuse:begin py-005
@app.get("/preview/assembled")
def preview_assembled():
    """Only the authority is attacker-controlled; the URL is built by the app.

    Detectors that look for a tainted value reaching the sink whole tend to miss
    this shape, because the string at the sink is a literal template.
    """
    host = request.args.get("host", ALLOWED_HOST)
    path = request.args.get("path", "/status")
    url = f"http://{host}{path}"
    resp = requests.get(url, timeout=TIMEOUT)
    return _ok(resp.text, status=resp.status_code, resolved=url)
# @ssrefuse:end py-005


# ---------------------------------------------------------------------------
# Denylists
# ---------------------------------------------------------------------------

# @ssrefuse:begin py-006
@app.get("/preview/denylist-string")
def preview_denylist_string():
    """Rejects URLs whose raw text mentions a blocked address.

    The check never parses the URL, so any alternative spelling of the same
    address walks straight through.
    """
    url = request.args.get("url", "")
    for bad in BLOCKED_SUBSTRINGS:
        if bad in url.lower():
            return _blocked(f"denylisted substring {bad}")
    resp = requests.get(url, timeout=TIMEOUT)
    return _ok(resp.text, status=resp.status_code)
# @ssrefuse:end py-006


# @ssrefuse:begin py-007
@app.get("/preview/denylist-host")
def preview_denylist_host():
    """Parses the URL first, then denylists the hostname.

    Stronger than the string check, and still a denylist: it only knows the
    names someone thought to write down.
    """
    url = request.args.get("url", "")
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    if host in BLOCKED_HOSTS:
        return _blocked(f"denylisted host {host}")
    resp = requests.get(url, timeout=TIMEOUT)
    return _ok(resp.text, status=resp.status_code)
# @ssrefuse:end py-007


# ---------------------------------------------------------------------------
# Allowlists that operate on the URL as text
# ---------------------------------------------------------------------------

# @ssrefuse:begin py-008
@app.get("/preview/allow-prefix")
def preview_allow_prefix():
    """Allowlist by string prefix: the authority boundary is not where the
    prefix ends, so the trusted name can be extended or demoted to userinfo."""
    url = request.args.get("url", "")
    if not url.startswith(ALLOWED_ORIGIN):
        return _blocked("origin not allowlisted")
    resp = requests.get(url, timeout=TIMEOUT)
    return _ok(resp.text, status=resp.status_code)
# @ssrefuse:end py-008


# @ssrefuse:begin py-009
@app.get("/preview/allow-substring")
def preview_allow_substring():
    """Allowlist by substring: the trusted name can appear anywhere, including
    in a path or a query parameter of someone else's URL."""
    url = request.args.get("url", "")
    if ALLOWED_HOST not in url:
        return _blocked("allowlisted host not present in url")
    resp = requests.get(url, timeout=TIMEOUT)
    return _ok(resp.text, status=resp.status_code)
# @ssrefuse:end py-009


# @ssrefuse:begin py-010
@app.get("/preview/allow-regex")
def preview_allow_regex():
    """Allowlist by regex with no end anchor."""
    url = request.args.get("url", "")
    if not re.match(r"https?://" + re.escape(ALLOWED_HOST), url):
        return _blocked("url does not match allowlist pattern")
    resp = requests.get(url, timeout=TIMEOUT)
    return _ok(resp.text, status=resp.status_code)
# @ssrefuse:end py-010


# ---------------------------------------------------------------------------
# Allowlists that parse the URL properly
# ---------------------------------------------------------------------------

# @ssrefuse:begin py-011
@app.get("/preview/allow-host-redirects")
def preview_allow_host_redirects():
    """Exact hostname allowlist on the URL the app was given.

    The guard describes the first request only; the client then follows wherever
    that host points it.
    """
    url = request.args.get("url", "")
    if (urllib.parse.urlparse(url).hostname or "").lower() != ALLOWED_HOST:
        return _blocked("host not allowlisted")
    resp = requests.get(url, timeout=TIMEOUT)
    return _ok(resp.text, status=resp.status_code, final_url=resp.url)
# @ssrefuse:end py-011


# @ssrefuse:begin py-012
@app.get("/preview/allow-host-noredirect")
def preview_allow_host_noredirect():
    """Exact hostname allowlist, redirects refused."""
    url = request.args.get("url", "")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return _blocked("scheme not allowed")
    if (parsed.hostname or "").lower() != ALLOWED_HOST:
        return _blocked("host not allowlisted")
    resp = requests.get(url, timeout=TIMEOUT, allow_redirects=False)
    return _ok(resp.text, status=resp.status_code)
# @ssrefuse:end py-012


# @ssrefuse:begin py-013
@app.get("/preview/resolve-check")
def preview_resolve_check():
    """Resolves the hostname, rejects non-public addresses, then fetches by name.

    The address that was validated and the address that is connected to come
    from two separate lookups.
    """
    url = request.args.get("url", "")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return _blocked("scheme not allowed")
    host = parsed.hostname or ""
    try:
        addr = socket.gethostbyname(host)
    except OSError:
        return _blocked("host does not resolve")
    if not ipaddress.ip_address(addr).is_global:
        return _blocked(f"non-public address {addr}")
    resp = requests.get(url, timeout=TIMEOUT, allow_redirects=False)
    return _ok(resp.text, status=resp.status_code, validated_address=addr)
# @ssrefuse:end py-013


# @ssrefuse:begin py-014
@app.get("/preview/resolve-pin")
def preview_resolve_pin():
    """Resolves once, validates the address, and connects to that same address.

    The hostname is carried in the Host header instead of being resolved again,
    and redirects are refused, so there is no second lookup to win.
    """
    url = request.args.get("url", "")
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return _blocked("scheme not allowed")
    host = parsed.hostname or ""
    try:
        addr = socket.gethostbyname(host)
    except OSError:
        return _blocked("host does not resolve")
    if not ipaddress.ip_address(addr).is_global:
        return _blocked(f"non-public address {addr}")
    pinned = parsed._replace(netloc=addr if not parsed.port else f"{addr}:{parsed.port}")
    resp = requests.get(urllib.parse.urlunparse(pinned), timeout=TIMEOUT,
                        allow_redirects=False, headers={"Host": host})
    return _ok(resp.text, status=resp.status_code, connected_to=addr)
# @ssrefuse:end py-014


# @ssrefuse:begin py-015
@app.get("/preview/scheme-only")
def preview_scheme_only():
    """Checks the scheme and nothing else."""
    url = request.args.get("url", "")
    if urllib.parse.urlparse(url).scheme not in ("http", "https"):
        return _blocked("scheme not allowed")
    resp = requests.get(url, timeout=TIMEOUT)
    return _ok(resp.text, status=resp.status_code)
# @ssrefuse:end py-015


# ---------------------------------------------------------------------------
# Sink diversity
# ---------------------------------------------------------------------------

# @ssrefuse:begin py-016
@app.get("/preview/urlopen")
def preview_urlopen():
    """urllib sink with no guard: also accepts file:// and other handlers."""
    url = request.args.get("url", "")
    with urllib.request.urlopen(url, timeout=TIMEOUT) as handle:
        body = handle.read(2000).decode("utf-8", "replace")
    return _ok(body)
# @ssrefuse:end py-016


# @ssrefuse:begin py-017
@app.get("/preview/httpx")
def preview_httpx():
    """httpx sink behind the same denylist as py-007."""
    url = request.args.get("url", "")
    host = (urllib.parse.urlparse(url).hostname or "").lower()
    if host in BLOCKED_HOSTS:
        return _blocked(f"denylisted host {host}")
    resp = httpx.get(url, timeout=TIMEOUT)
    return _ok(resp.text, status=resp.status_code)
# @ssrefuse:end py-017


# @ssrefuse:begin py-018
@app.get("/preview/curl")
def preview_curl():
    """The fetch is delegated to the curl binary, so the sink is a subprocess."""
    url = request.args.get("url", "")
    proc = subprocess.run(["curl", "-s", "--max-time", str(TIMEOUT), url],
                          capture_output=True, text=True, timeout=TIMEOUT + 2)
    return _ok(proc.stdout)
# @ssrefuse:end py-018


# ---------------------------------------------------------------------------
# Flows that defeat single-pass reasoning
# ---------------------------------------------------------------------------

# @ssrefuse:begin py-019
@app.post("/preview/enqueue")
def preview_enqueue():
    """Stores the URL. No fetch happens here, so this route is not the sink."""
    payload = request.get_json(silent=True) or {}
    job_id = str(len(PREVIEW_QUEUE) + 1)
    PREVIEW_QUEUE[job_id] = {"url": payload.get("url", ""), "state": "pending"}
    return jsonify({"ok": True, "job_id": job_id})
# @ssrefuse:end py-019


# @ssrefuse:begin py-020
@app.get("/preview/run/<job_id>")
def preview_run(job_id: str):
    """Fetches a URL stored by an earlier request: a second-order flow.

    Nothing tainted appears in this function; the taint was persisted by
    py-019 and is read back out of module state here.
    """
    job = PREVIEW_QUEUE.get(job_id)
    if job is None:
        return jsonify({"ok": False, "error": "no such job"}), 404
    resp = requests.get(job["url"], timeout=TIMEOUT)
    job["state"] = "done"
    return _ok(resp.text, status=resp.status_code)
# @ssrefuse:end py-020


# @ssrefuse:begin py-021
@app.get("/preview/checked-wrong-value")
def preview_checked_wrong_value():
    """A correct allowlist check applied to the wrong variable.

    ``candidate`` is validated; ``raw`` is fetched. Decoding first looks like
    hardening, and it is what creates the gap: a percent-encoded delimiter means
    the decoded copy and the raw copy have different authorities.

    Half-correct code like this
    is the ordinary shape of the bug in real applications, and it is why a
    detector must bind a guard to the value that reaches the sink rather than to
    whatever check appears nearby.
    """
    raw = request.args.get("url", "")
    candidate = urllib.parse.unquote(raw)
    parsed = urllib.parse.urlparse(candidate)
    if (parsed.hostname or "").lower() != ALLOWED_HOST:
        return _blocked("host not allowlisted")
    resp = requests.get(raw, timeout=TIMEOUT, allow_redirects=False)
    return _ok(resp.text, status=resp.status_code)
# @ssrefuse:end py-021


# ---------------------------------------------------------------------------
# Routes that must never be reported: the false-positive controls
# ---------------------------------------------------------------------------

# @ssrefuse:begin py-022
@app.get("/status/upstream")
def status_upstream():
    """Fetches a fixed URL. No user input is involved anywhere in this route."""
    resp = requests.get(f"{ALLOWED_ORIGIN}/health", timeout=TIMEOUT,
                        allow_redirects=False)
    return _ok(resp.text, status=resp.status_code)
# @ssrefuse:end py-022


# @ssrefuse:begin py-023
@app.get("/preview/path-only")
def preview_path_only():
    """User input reaches the URL, but only the path, and the authority is
    fixed. The validation rejects anything that could end the path component
    and take over the authority."""
    path = request.args.get("path", "/status")
    if not path.startswith("/") or any(ch in path for ch in "@?#\\") or "//" in path:
        return _blocked("invalid path")
    resp = requests.get(f"{ALLOWED_ORIGIN}{path}", timeout=TIMEOUT,
                        allow_redirects=False)
    return _ok(resp.text, status=resp.status_code)
# @ssrefuse:end py-023


@app.get("/")
def index():
    routes = sorted(
        f"{sorted(rule.methods & {'GET', 'POST'})[0]} {rule.rule}"
        for rule in app.url_map.iter_rules() if rule.endpoint != "static"
    )
    return jsonify({"app": "ssrefuse-flask-lab", "routes": routes})


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 19080
    # Printed so the harness can confirm which build is answering, read out of
    # the running process rather than off disk.
    print(f"LAB-READY name=flask_ssrf port={port} "
          f"routes={len(list(app.url_map.iter_rules())) - 1}", flush=True)
    app.run(host="127.0.0.1", port=port, threaded=True, debug=False)
