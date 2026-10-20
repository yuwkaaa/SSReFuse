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

ALIAS_IPS = [f"{IP_PUBLIC}/32", f"{IP_OOB}/32", f"{IP_CGNAT}/32", f"{IP_METADATA}/32"]

# --- ports -----------------------------------------------------------------
PORT_INTERNAL_ADMIN = 19001
PORT_HTTP = 80
PORT_DNS = 53
LAB_PORTS = {"python": 19080, "javascript": 19081, "php": 19082}

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

INTERNAL_MARKERS = (MARKER_INTERNAL, MARKER_METADATA, MARKER_CGNAT, MARKER_LOCALFILE)

SANDBOX_ROOT = "/tmp/ssrefuse-sandbox"
SECRET_FILE = f"{SANDBOX_ROOT}/secret.txt"

# Convenience URLs used by payload templates and by the lab allowlists.
URL_INTERNAL = f"http://{IP_INTERNAL}:{PORT_INTERNAL_ADMIN}/admin"
URL_METADATA = f"http://{IP_METADATA}/latest/meta-data/iam/security-credentials/"
URL_PUBLIC = f"http://{ALLOWED_HOST}/"
