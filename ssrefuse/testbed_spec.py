"""Single source of truth for the hermetic testbed: IPs, ports, DNS zone, canaries.

Every address below lives only inside an unprivileged network namespace created by
``ssrefuse.harness.sandbox``. Nothing here is reachable from the host, and the
namespace has no route to the internet -- see ``tests/test_sandbox_isolation.py``,
which asserts both directions before any measurement is allowed to run.
"""
from __future__ import annotations

ZONE = "ssrefuse.test"

# --- addresses -------------------------------------------------------------
# IP_PUBLIC stands in for "a host on the public internet". 192.88.99.0/24 is the
# deprecated 6to4 relay anycast prefix (RFC 7526): unallocated, unrouted, and --
# unlike the RFC 5737 documentation ranges -- still classified as global by
# Python's ipaddress module, so a guard that rejects private IPs accepts it.
IP_PUBLIC = "192.88.99.10"
IP_OOB = "192.88.99.20"
IP_CGNAT = "100.64.0.10"          # RFC 6598 shared space: neither private nor global
IP_METADATA = "169.254.169.254"   # cloud metadata address, served locally by a fake
IP_INTERNAL = "127.0.0.1"
IP_RFC1918 = "10.0.0.10"          # "another host on the corporate network"
# The link-local metadata address is not one address in practice. These are the
# ones a real instance answers on, and they do not behave the same way, which
# is the point of having more than one.
IP_METADATA_ECS = "169.254.170.2"      # ECS / Fargate task metadata
IP_METADATA_ALIBABA = "100.100.100.200"  # Alibaba Cloud metadata

ALIAS_IPS = [f"{IP_PUBLIC}/32", f"{IP_OOB}/32", f"{IP_CGNAT}/32", f"{IP_METADATA}/32",
             f"{IP_RFC1918}/32", f"{IP_METADATA_ECS}/32", f"{IP_METADATA_ALIBABA}/32"]

# --- ports -----------------------------------------------------------------
PORT_INTERNAL_ADMIN = 19001
PORT_HTTP = 80
PORT_DNS = 53
LAB_PORTS = {"python": 19080, "javascript": 19081, "php": 19082}

# The internal service range. A testbed with one admin endpoint behind it makes
# every guard look like it only has to know about one thing; the services an
# SSRF is actually aimed at sit on well-known ports and speak either HTTP or a
# line protocol, and which of the two decides whether a sink can reach them at
# all. These numbers are the real default ports so that lab code and payloads
# look like the ones in the wild; the services behind them are fakes that serve
# a canary and nothing else.
PORT_DOCKER = 2375         # Docker Engine API, unauthenticated by default
PORT_ELASTIC = 9200        # Elasticsearch
PORT_CONSUL = 8500         # Consul HTTP API
PORT_ACTUATOR = 8081       # Spring Boot actuator
PORT_REDIS = 6379          # line protocol, not HTTP
PORT_MEMCACHED = 11211     # line protocol, not HTTP
PORT_CLOSED = 19999        # nothing listens here: the negative control for
                           # "the probe reached a port" versus "a service answered"

# --- DNS zone --------------------------------------------------------------
# A list with more than one address is served round-robin with TTL 0, which is
# how the DNS-rebinding variant gets a real time-of-check/time-of-use window.
DNS_ZONE: dict[str, list[str]] = {
    f"public.{ZONE}":   [IP_PUBLIC],
    f"internal.{ZONE}": [IP_INTERNAL],
    f"metadata.{ZONE}": [IP_METADATA],
    f"cgnat.{ZONE}":    [IP_CGNAT],
    f"oob.{ZONE}":      [IP_OOB],
    f"rebind.{ZONE}":   [IP_PUBLIC, IP_INTERNAL],
    # Names for the internal service range, so a payload can reach them without
    # an address appearing in the URL at all.
    f"docker.{ZONE}":   [IP_INTERNAL],
    f"redis.{ZONE}":    [IP_INTERNAL],
    f"intranet.{ZONE}": [IP_RFC1918],
}
# Suffix whose queries are logged as out-of-band evidence (blind SSRF oracle).
OOB_DNS_SUFFIX = f".oob.{ZONE}"

# --- hosts the labs are configured to trust --------------------------------
ALLOWED_HOST = f"public.{ZONE}"
ALLOWED_ORIGIN = f"http://public.{ZONE}"

# --- canary markers --------------------------------------------------------
# A probe counts as reaching an internal target only when the matching marker
# shows up in the response body, or when the target's own access log records the
# hit (blind case). MARKER_BENIGN is the opposite control: seeing it means the
# fetch succeeded against the allowed host, which is not a finding.
MARKER_INTERNAL = "SSREFUSE-INTERNAL-ADMIN-SECRET"
MARKER_METADATA = "SSREFUSE-METADATA-CREDENTIALS"
MARKER_CGNAT = "SSREFUSE-CGNAT-SERVICE"
MARKER_LOCALFILE = "SSREFUSE-LOCAL-FILE-SECRET"
MARKER_BENIGN = "SSREFUSE-PUBLIC-BENIGN"
MARKER_OOB = "SSREFUSE-OOB-CANARY"

# The internal service range, one canary each so a probe that reaches two of
# them cannot be mistaken for a probe that reached one twice.
MARKER_DOCKER = "SSREFUSE-DOCKER-ENGINE-API"
MARKER_ELASTIC = "SSREFUSE-ELASTIC-CLUSTER"
MARKER_CONSUL = "SSREFUSE-CONSUL-KV-SECRET"
MARKER_ACTUATOR = "SSREFUSE-ACTUATOR-ENV-SECRET"
MARKER_RFC1918 = "SSREFUSE-INTRANET-APP"
MARKER_REDIS = "SSREFUSE-REDIS-BANNER"
MARKER_MEMCACHED = "SSREFUSE-MEMCACHED-BANNER"
# Metadata services that answer only when a request header is present. An SSRF
# that controls the URL and nothing else cannot produce that header, so these
# markers are the ones a run is expected NOT to see. They are separate canaries
# precisely so that "did not reach it" is a measurement and not an absence.
MARKER_METADATA_GUARDED = "SSREFUSE-METADATA-HEADER-GATED"
MARKER_METADATA_ECS = "SSREFUSE-METADATA-ECS-TASK"
MARKER_METADATA_ALIBABA = "SSREFUSE-METADATA-ALIBABA"

INTERNAL_MARKERS = (MARKER_INTERNAL, MARKER_METADATA, MARKER_CGNAT, MARKER_LOCALFILE,
                    MARKER_DOCKER, MARKER_ELASTIC, MARKER_CONSUL, MARKER_ACTUATOR,
                    MARKER_RFC1918, MARKER_REDIS, MARKER_MEMCACHED,
                    MARKER_METADATA_GUARDED, MARKER_METADATA_ECS, MARKER_METADATA_ALIBABA)

SANDBOX_ROOT = "/tmp/ssrefuse-sandbox"
SECRET_FILE = f"{SANDBOX_ROOT}/secret.txt"

# Convenience URLs used by payload templates and by the lab allowlists.
URL_INTERNAL = f"http://{IP_INTERNAL}:{PORT_INTERNAL_ADMIN}/admin"
URL_DOCKER = f"http://{IP_INTERNAL}:{PORT_DOCKER}/version"
URL_METADATA = f"http://{IP_METADATA}/latest/meta-data/iam/security-credentials/"
URL_PUBLIC = f"http://{ALLOWED_HOST}/"
