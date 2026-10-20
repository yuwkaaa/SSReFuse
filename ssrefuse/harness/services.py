"""Testbed services: authoritative DNS, internal targets, and the OOB canary.

All of these run inside the sandbox namespace. Every service appends to one
JSONL access log, which is the oracle for blind SSRF: a probe that returns no
body still leaves a row here, and a probe that was blocked leaves none.
"""
from __future__ import annotations

import itertools
import json
import os
import socket
import socketserver
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dnslib import RR, QTYPE, A, RCODE
from dnslib.server import DNSServer, BaseResolver

from ssrefuse import testbed_spec as spec


class AccessLog:
    """Append-only JSONL log shared by every testbed service."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "a").close()

    def record(self, service: str, **fields) -> None:
        row = {"ts": time.time(), "service": service, **fields}
        line = json.dumps(row, sort_keys=True)
        with self._lock:
            with open(self.path, "a") as fh:
                fh.write(line + "\n")
                fh.flush()


class _Quiet:
    """dnslib insists on a logger object; this one drops everything."""

    def __getattr__(self, _name):
        return lambda *a, **k: None


class ZoneResolver(BaseResolver):
    """Authoritative resolver for the testbed zone.

    Names mapped to several addresses are answered round-robin with TTL 0, which
    is what gives the DNS-rebinding variant a real check/use window. Anything
    outside the zone is NXDOMAIN, so a lab can never accidentally reach a real
    host even if the namespace did have a route out.
    """

    def __init__(self, log: AccessLog):
        self.log = log
        self._cycles = {
            name.rstrip(".") + ".": itertools.cycle(ips)
            for name, ips in spec.DNS_ZONE.items()
        }
        self._lock = threading.Lock()
        # Wildcard suffixes. The internal and metadata wildcards model an
        # attacker-controlled name that resolves to a target address, which is
        # what turns a text-level allowlist bypass into a reachable request.
        self._suffixes = [
            (f".evil.{spec.ZONE}.", spec.IP_PUBLIC),
            (f".oob.{spec.ZONE}.", spec.IP_OOB),
            (f".internal.{spec.ZONE}.", spec.IP_INTERNAL),
            (f".metadata.{spec.ZONE}.", spec.IP_METADATA),
            (f".cgnat.{spec.ZONE}.", spec.IP_CGNAT),
        ]

    def _lookup(self, qname: str) -> str | None:
        with self._lock:
            if qname in self._cycles:
                return next(self._cycles[qname])
        for suffix, ip in self._suffixes:
            if qname.endswith(suffix):
                return ip
        return None

    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname).lower()
        qtype = QTYPE[request.q.qtype]
        ip = self._lookup(qname) if qtype in ("A", "ANY") else None
        if ip is None:
            reply.header.rcode = RCODE.NXDOMAIN
        else:
            reply.add_answer(RR(qname, QTYPE.A, ttl=0, rdata=A(ip)))
        # A DNS query alone is out-of-band evidence: it proves the sink parsed
        # and resolved an attacker-supplied host even when the connection fails.
        if qname.endswith(f".oob.{spec.ZONE}.") or qname == f"oob.{spec.ZONE}.":
            self.log.record("dns-oob", qname=qname, qtype=qtype, answer=ip,
                            marker=spec.MARKER_OOB)
        else:
            self.log.record("dns", qname=qname, qtype=qtype, answer=ip)
        return reply


def _handler(service: str, log: AccessLog, dispatch):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "ssrefuse-testbed"

        def _run(self, method: str):
            parsed = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            log.record(service, method=method, path=self.path,
                       host_header=self.headers.get("Host", ""),
                       ua=self.headers.get("User-Agent", ""),
                       client=self.client_address[0])
            status, headers, body = dispatch(parsed.path, query, self.headers)
            raw = body.encode() if isinstance(body, str) else body
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(raw)

        def do_GET(self):
            self._run("GET")

        def do_POST(self):
            self._run("POST")

        def do_HEAD(self):
            self._run("HEAD")

        def log_message(self, *a):
            pass

    return Handler


class _IPv6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def _internal_admin(path, query, headers):
    if path.startswith("/admin"):
        return 200, {"Content-Type": "text/plain"}, (
            f"{spec.MARKER_INTERNAL}\nrole=admin\ntoken=ssrefuse-internal-token\n")
    return 200, {"Content-Type": "text/plain"}, "internal service root\n"


def _metadata(path, query, headers):
    """The link-local metadata address, with the layouts real clouds serve.

    Shapes mirror the published ones so that lab code and payloads look like
    the ones in the wild; the contents are fabricated and the address is local
    to the sandbox.

    The important part is that three of these branches require a *request
    header*. GCP wants `Metadata-Flavor: Google`, Azure wants `Metadata: true`,
    and IMDSv2 wants a token obtained with a PUT. An SSRF that controls the URL
    and nothing else cannot produce any of them, so those branches answer
    without the canary. A run is expected not to see MARKER_METADATA_GUARDED,
    and the harness records that as a measured negative rather than as silence:
    "the cloud's own mitigation held" and "the guard held" are different
    findings and a matrix that cannot tell them apart is not worth reading.
    """
    if path.startswith("/computeMetadata"):
        if headers.get("Metadata-Flavor") != "Google":
            return 403, {"Content-Type": "text/plain"}, (
                "Missing Metadata-Flavor:Google header.\n")
        return 200, {"Content-Type": "text/plain"}, (
            f"{spec.MARKER_METADATA_GUARDED}\ngcp service account token\n")
    if path.startswith("/metadata/instance"):
        if headers.get("Metadata") != "true":
            return 400, {"Content-Type": "application/json"}, json.dumps(
                {"error": "Required metadata header not specified"})
        return 200, {"Content-Type": "application/json"}, json.dumps(
            {"compute": {"name": spec.MARKER_METADATA_GUARDED}}, indent=2)
    if path.startswith("/latest/api/token"):
        # IMDSv2 issues the token only for PUT, which an SSRF that can only
        # cause a GET cannot send.
        return 405, {"Content-Type": "text/plain"}, (
            "IMDSv2 token requests must be PUT\n")
    if "security-credentials" in path:
        if headers.get("X-aws-ec2-metadata-token"):
            return 200, {"Content-Type": "text/plain"}, (
                f"{spec.MARKER_METADATA_GUARDED}\nimdsv2 credentials\n")
        return 200, {"Content-Type": "text/plain"}, json.dumps({
            "Code": "Success",
            "AccessKeyId": "ASIA" + "X" * 16,
            "SecretAccessKey": spec.MARKER_METADATA,
            "Token": "ssrefuse-fake-session-token",
        }, indent=2)
    if path.rstrip("/").endswith("/iam"):
        return 200, {"Content-Type": "text/plain"}, "security-credentials/\n"
    return 200, {"Content-Type": "text/plain"}, f"{spec.MARKER_METADATA}\nami-id\nhostname\niam/\n"


def _metadata_ecs(path, query, headers):
    """Task metadata, which needs no header at all -- the reachable one."""
    return 200, {"Content-Type": "application/json"}, json.dumps(
        {"TaskARN": "arn:aws:ecs:ssrefuse:fake", "Secret": spec.MARKER_METADATA_ECS},
        indent=2)


def _metadata_alibaba(path, query, headers):
    return 200, {"Content-Type": "text/plain"}, (
        f"{spec.MARKER_METADATA_ALIBABA}\nram/security-credentials/\n")


def _cgnat(path, query, headers):
    return 200, {"Content-Type": "text/plain"}, f"{spec.MARKER_CGNAT}\n"


def _public_site(path, query, headers):
    """Attacker-reachable public host.

    Serves both the allowlisted partner name and the attacker's own name, so the
    same process backs the open-redirect chain and the plain benign fetch.
    """
    if path == "/redirect":
        target = (query.get("to") or [spec.URL_INTERNAL])[0]
        return 302, {"Location": target, "Content-Type": "text/plain"}, "redirecting\n"
    if path == "/redirect307":
        # 307 preserves the method and the body where 302 may not. A guard that
        # reasons only about the first request cannot tell the two apart.
        target = (query.get("to") or [spec.URL_INTERNAL])[0]
        return 307, {"Location": target, "Content-Type": "text/plain"}, "redirecting\n"
    if path == "/chain":
        target = (query.get("to") or [spec.URL_INTERNAL])[0]
        hops = int((query.get("n") or ["3"])[0])
        if hops > 1:
            nxt = (f"http://{spec.ALLOWED_HOST}/chain?to="
                   f"{urllib.parse.quote(target, safe='')}&n={hops - 1}")
            return 302, {"Location": nxt, "Content-Type": "text/plain"}, "hop\n"
        return 302, {"Location": target, "Content-Type": "text/plain"}, "last hop\n"
    if path == "/slow":
        time.sleep(float((query.get("s") or ["2"])[0]))
        return 200, {"Content-Type": "text/plain"}, f"{spec.MARKER_BENIGN}-slow\n"
    return 200, {"Content-Type": "text/plain"}, f"{spec.MARKER_BENIGN}\nharmless partner payload\n"


def _oob(path, query, headers):
    return 200, {"Content-Type": "text/plain"}, f"{spec.MARKER_OOB}\n"


# --- the internal service range -------------------------------------------
# A testbed with a single admin endpoint behind it measures a guard against one
# thing. The services an SSRF is actually pointed at are a range: an
# unauthenticated container API, a search cluster, a service-discovery KV
# store, a framework's own diagnostics endpoint, another host on the corporate
# network, and two that do not speak HTTP at all. Each serves a canary and
# nothing else; the shapes below only exist so that lab code and payloads look
# like the ones they are modelled on.

def _docker_api(path, query, headers):
    if path.startswith("/version"):
        return 200, {"Content-Type": "application/json"}, json.dumps(
            {"Version": "0.0.0-ssrefuse-fake", "ApiVersion": "1.45",
             "Secret": spec.MARKER_DOCKER}, indent=2)
    if path.startswith("/containers"):
        return 200, {"Content-Type": "application/json"}, json.dumps(
            [{"Id": "ssrefuse-fake", "Image": spec.MARKER_DOCKER}], indent=2)
    return 200, {"Content-Type": "text/plain"}, f"{spec.MARKER_DOCKER}\n"


def _elasticsearch(path, query, headers):
    if path.rstrip("/") in ("", "/"):
        return 200, {"Content-Type": "application/json"}, json.dumps(
            {"cluster_name": spec.MARKER_ELASTIC, "tagline": "You Know, for Canaries"},
            indent=2)
    return 200, {"Content-Type": "application/json"}, json.dumps(
        {"hits": {"total": 1, "hits": [{"_source": {"secret": spec.MARKER_ELASTIC}}]}},
        indent=2)


def _consul(path, query, headers):
    return 200, {"Content-Type": "application/json"}, json.dumps(
        [{"Key": "ssrefuse/secret", "Value": spec.MARKER_CONSUL}], indent=2)


def _actuator(path, query, headers):
    return 200, {"Content-Type": "application/json"}, json.dumps(
        {"propertySources": [{"name": "systemEnvironment",
                              "properties": {"API_TOKEN": {"value": spec.MARKER_ACTUATOR}}}]},
        indent=2)


def _intranet(path, query, headers):
    return 200, {"Content-Type": "text/plain"}, (
        f"{spec.MARKER_RFC1918}\ninternal corporate application\n")


HTTP_SERVICES = [
    ("internal-admin", spec.IP_INTERNAL, spec.PORT_INTERNAL_ADMIN, _internal_admin),
    # The same service on IPv6 loopback. Without this listener an [::1] payload
    # fails at connect and the result reads as "the guard held" when in fact the
    # guard never saw it -- the target simply was not there.
    ("internal-admin6", "::1", spec.PORT_INTERNAL_ADMIN, _internal_admin),
    ("metadata", spec.IP_METADATA, spec.PORT_HTTP, _metadata),
    ("metadata-ecs", spec.IP_METADATA_ECS, spec.PORT_HTTP, _metadata_ecs),
    ("metadata-alibaba", spec.IP_METADATA_ALIBABA, spec.PORT_HTTP, _metadata_alibaba),
    ("cgnat", spec.IP_CGNAT, spec.PORT_HTTP, _cgnat),
    ("public-site", spec.IP_PUBLIC, spec.PORT_HTTP, _public_site),
    ("oob-http", spec.IP_OOB, spec.PORT_HTTP, _oob),
    ("docker-api", spec.IP_INTERNAL, spec.PORT_DOCKER, _docker_api),
    ("elasticsearch", spec.IP_INTERNAL, spec.PORT_ELASTIC, _elasticsearch),
    ("consul", spec.IP_INTERNAL, spec.PORT_CONSUL, _consul),
    ("actuator", spec.IP_INTERNAL, spec.PORT_ACTUATOR, _actuator),
    ("intranet", spec.IP_RFC1918, spec.PORT_HTTP, _intranet),
]

# Services that do not speak HTTP. They exist because the question "can this
# sink reach a line protocol" has a different answer from "can this sink reach
# an internal HTTP service", and only a sink that can speak gopher:// or
# dict:// -- in this corpus, the curl subprocess -- can answer it yes. The
# first bytes the client sends are logged verbatim, because for a blind
# protocol that is the entire evidence that anything arrived.
LINE_SERVICES = [
    ("redis", spec.IP_INTERNAL, spec.PORT_REDIS, spec.MARKER_REDIS, "+%s\r\n"),
    ("memcached", spec.IP_INTERNAL, spec.PORT_MEMCACHED, spec.MARKER_MEMCACHED, "VERSION %s\r\n"),
]


def _line_server(name: str, address: str, port: int, marker: str, template: str,
                 log: AccessLog):
    """A TCP listener that records what was sent to it and answers a banner."""

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            # Short, because the evidence is the log row rather than the reply:
            # a client that connects and waits must still produce that row
            # quickly enough for the probe's own timeout.
            self.request.settimeout(1.0)
            received = b""
            try:
                while len(received) < 2048:
                    chunk = self.request.recv(1024)
                    if not chunk:
                        break
                    received += chunk
                    if b"\n" in chunk:
                        break
            except OSError:
                pass
            log.record(name, protocol="tcp", port=port,
                       client=self.client_address[0],
                       bytes_received=len(received),
                       first_bytes=received[:200].decode("utf-8", "replace"),
                       marker=marker)
            try:
                self.request.sendall((template % marker).encode())
            except OSError:
                pass

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    return Server((address, port), Handler)


def start_all(log: AccessLog) -> list:
    """Start DNS plus every target. Raises if any address cannot be bound."""
    servers: list = []
    for name, addr, port, dispatch in HTTP_SERVICES:
        server_cls = _IPv6Server if ":" in addr else ThreadingHTTPServer
        srv = server_cls((addr, port), _handler(name, log, dispatch))
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True, name=name).start()
        servers.append(srv)
    for name, addr, port, marker, template in LINE_SERVICES:
        srv = _line_server(name, addr, port, marker, template, log)
        threading.Thread(target=srv.serve_forever, daemon=True, name=name).start()
        servers.append(srv)
    dns = DNSServer(ZoneResolver(log), port=spec.PORT_DNS,
                    address=spec.IP_INTERNAL, logger=_Quiet())
    dns.start_thread()
    return servers


def assert_ready(timeout: float = 10.0) -> dict[str, str]:
    """Probe every service and return the evidence. Never returns on partial setup.

    This is deliberately an assertion and not a readiness poll that gives up
    quietly: a measurement run on a half-built testbed produces negative results
    that look exactly like real ones.
    """
    import http.client

    deadline = time.time() + timeout
    evidence: dict[str, str] = {}
    checks = [
        ("internal-admin", spec.IP_INTERNAL, spec.PORT_INTERNAL_ADMIN, "/admin", spec.MARKER_INTERNAL),
        ("internal-admin6", "::1", spec.PORT_INTERNAL_ADMIN, "/admin", spec.MARKER_INTERNAL),
        ("metadata", spec.IP_METADATA, spec.PORT_HTTP, "/latest/meta-data/", spec.MARKER_METADATA),
        ("cgnat", spec.IP_CGNAT, spec.PORT_HTTP, "/", spec.MARKER_CGNAT),
        ("public-site", spec.IP_PUBLIC, spec.PORT_HTTP, "/", spec.MARKER_BENIGN),
        ("oob-http", spec.IP_OOB, spec.PORT_HTTP, "/", spec.MARKER_OOB),
        ("docker-api", spec.IP_INTERNAL, spec.PORT_DOCKER, "/version", spec.MARKER_DOCKER),
        ("elasticsearch", spec.IP_INTERNAL, spec.PORT_ELASTIC, "/", spec.MARKER_ELASTIC),
        ("consul", spec.IP_INTERNAL, spec.PORT_CONSUL, "/v1/kv/?recurse", spec.MARKER_CONSUL),
        ("actuator", spec.IP_INTERNAL, spec.PORT_ACTUATOR, "/actuator/env", spec.MARKER_ACTUATOR),
        ("intranet", spec.IP_RFC1918, spec.PORT_HTTP, "/", spec.MARKER_RFC1918),
        ("metadata-ecs", spec.IP_METADATA_ECS, spec.PORT_HTTP, "/v2/metadata",
         spec.MARKER_METADATA_ECS),
        ("metadata-alibaba", spec.IP_METADATA_ALIBABA, spec.PORT_HTTP, "/latest/meta-data/",
         spec.MARKER_METADATA_ALIBABA),
    ]
    for name, addr, port, path, marker in checks:
        last = "not attempted"
        while time.time() < deadline:
            try:
                conn = http.client.HTTPConnection(addr, port, timeout=2)
                conn.request("GET", path)
                body = conn.getresponse().read().decode("utf-8", "replace")
                conn.close()
                if marker not in body:
                    raise AssertionError(f"{name}: marker missing from body {body[:80]!r}")
                evidence[name] = f"{addr}:{port}{path} -> marker present"
                break
            except Exception as exc:  # noqa: BLE001 - reported verbatim below
                last = f"{type(exc).__name__}: {exc}"
                time.sleep(0.1)
        else:
            raise AssertionError(f"testbed service {name} never became ready ({last})")

    # The line-protocol services answer a banner rather than HTTP, so they are
    # checked by sending nothing and reading what comes back. A service that is
    # not up here would turn every gopher:// and dict:// probe into a connect
    # error, which reads as "the guard held".
    for name, addr, port, marker, _template in LINE_SERVICES:
        last = "not attempted"
        while time.time() < deadline:
            try:
                with socket.create_connection((addr, port), timeout=2) as sock:
                    sock.settimeout(3)
                    # Send a line first. Neither of the services these imitate
                    # greets a client unprompted, and the handler answers once
                    # it has seen a line, so a readiness check that only reads
                    # would be measuring its own timeout.
                    sock.sendall(b"PING\r\n")
                    banner = sock.recv(256).decode("utf-8", "replace")
                if marker not in banner:
                    raise AssertionError(f"{name}: banner was {banner[:60]!r}")
                evidence[name] = f"{addr}:{port} -> banner carries marker"
                break
            except Exception as exc:  # noqa: BLE001 - reported verbatim below
                last = f"{type(exc).__name__}: {exc}"
                time.sleep(0.1)
        else:
            raise AssertionError(f"testbed service {name} never became ready ({last})")

    # The closed port is a control in the other direction: a probe that reaches
    # it must fail, or "connected" means nothing anywhere else in the run.
    try:
        socket.create_connection((spec.IP_INTERNAL, spec.PORT_CLOSED), timeout=1).close()
        raise AssertionError(
            f"port {spec.PORT_CLOSED} was supposed to be closed but something answered; "
            f"refusing to measure")
    except OSError:
        evidence["closed-port-control"] = (
            f"{spec.IP_INTERNAL}:{spec.PORT_CLOSED} refuses connections, as required")

    for name in (f"internal.{spec.ZONE}", f"metadata.{spec.ZONE}", f"public.{spec.ZONE}",
                 f"intranet.{spec.ZONE}", f"docker.{spec.ZONE}"):
        evidence[f"dns:{name}"] = socket.gethostbyname(name)
    expected = {
        f"internal.{spec.ZONE}": spec.IP_INTERNAL,
        f"metadata.{spec.ZONE}": spec.IP_METADATA,
        f"public.{spec.ZONE}": spec.IP_PUBLIC,
        f"intranet.{spec.ZONE}": spec.IP_RFC1918,
        f"docker.{spec.ZONE}": spec.IP_INTERNAL,
    }
    for name, want in expected.items():
        got = evidence[f"dns:{name}"]
        if got != want:
            raise AssertionError(f"DNS zone wrong: {name} -> {got}, expected {want}")
    return evidence
