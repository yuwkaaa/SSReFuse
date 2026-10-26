# Evaluation protocol

## What a label means

`vulnerable`: at least one attacker-supplied input makes the application send a request to an
internal target (the admin service on `127.0.0.1:19001`, the metadata address, the CGNAT service) or
read a local file.

`safe`: no such input exists. Every safe variant carries a `why_safe` field, and the loader fails
validation if one does not. Note what the label does not say: `py-014` still fetches arbitrary public
URLs, which is the feature working. The label is about internal reach.

## Where ground truth comes from

Labels in `corpus/ground-truth.yaml` are a claim about the application. Which bypass technique works
is not written there, because the harness measures it. `bypasses_declared` lists the families each
variant was built to demonstrate, and the evaluator prints three things: the families that were
declared and reproduced, the declared ones that did not reproduce (a defect in the lab or the
catalog), and the ones that worked without being declared (informational, because declaring exists to catch
regressions).

Two integrity checks have teeth:

- a variant labelled `vulnerable` with no reproduced bypass is reported as an unproven label, not
  averaged into the totals
- a variant labelled `safe` that a payload got through is reported as a defect

Both lists are empty in the current run, and `ssrefuse report` exits non-zero if they are not.

## Controls that run every time

**Sandbox isolation.** Before any measurement, the namespace tries to open TCP to `1.1.1.1:443` and
to resolve `example.com`. Both must fail. If either succeeds the run raises rather than continuing,
because a lab talking to the real internet invalidates every result in the run.

**The benign control payload.** `B00_benign_allowed` fetches the allowlisted partner host. It must
succeed on every variant whose guard permits that host, and the report prints the count: 40 passes, 6
not applicable (two routes per lab take no URL, one per lab sends no request). A run where the
control fails everywhere means the prober is broken, and no negative result in it can be read as a
guard holding.

**The detector positive control, one per language.** `tests/fixtures/positive_control_python.py` and
`tests/fixtures/positive_control_javascript.js` are scanned in the same semgrep invocation as the
corpus. A detector tier is a tier across languages, so the counts are kept per control file and
every one of them has to be non-zero: a tier whose Python rules work and whose JavaScript rules load
nothing still reports a healthy total, and its JavaScript zeros would read as a clean corpus. A
configuration that reports nothing on any control is marked unusable and its numbers are not
comparable. This catches a rule file that failed to load, a pattern typo, and a semgrep upgrade that
changed pattern semantics, all of which otherwise produce a confident zero.

**The scanner control.** The JavaScript slicer has no parser behind it -- it is a character scan --
so `tests/fixtures/js_scanner_control.js` holds the constructs the scan has to get right (a `//`
inside a string, a regex literal full of brackets, a division, a template substitution, a JSDoc
block) and `tests/test_slicing_js.py` asserts counts that were read off the fixture by hand. A
scanner that mistakes a regex for a division returns a plausible wrong answer, and only a fixture
with a known answer tells the two apart.

**Lab identity.** Each probe run records the lab's pid, the pid holding the port according to the
socket table, and the ready line printed by the running process. Measurement is refused if the port
is held by anything else. The namespace is created fresh per run, so a server left over from an
earlier build cannot be present to begin with.

## What the testbed does, measured

Resolution behaviour inside the sandbox, which decides which payloads can reach anything:

| name | resolves to |
|---|---|
| `2130706433` | 127.0.0.1 |
| `0177.0.0.1` | 127.0.0.1 |
| `0x7f000001` | 127.0.0.1 |
| `127.1` | 127.0.0.1 |
| `0.0.0.0` | 0.0.0.0, which reaches a loopback-bound service on Linux |
| `127.0.0.1.` | does not resolve through glibc |
| `public.ssrefuse.test.internal.ssrefuse.test` | 127.0.0.1 |

The trailing-dot result is why the `B08_trailing_dot` family lists name forms rather than numeric
forms. The wildcard result is why a text-level allowlist bypass can reach an internal target at all:
without a name that both passes the prefix check and resolves internally, those payloads would land
on the public host and prove nothing.

Address classification by Python's `ipaddress`, which decides what the testbed's public host can be:

| address | `is_global` | `is_private` |
|---|---|---|
| `192.88.99.10` | True | False |
| `203.0.113.10` | False | True |
| `198.18.0.10` | False | True |
| `100.64.0.10` | False | False |
| `169.254.169.254` | False | True |

The RFC 5737 documentation ranges are classified private, so a guard of the form "resolve and reject
private addresses" rejects them, which would make the allowlisted host unreachable and every guard
look stronger than it is. `192.88.99.0/24` was deprecated by RFC 7526 and is classified global.
`100.64.0.0/10` is neither, which is why the CGNAT family defeats guards written as "reject RFC 1918
and loopback".

## What the runtimes do, measured

The JavaScript lab exists so that the same guard can be measured in a second runtime. Three runtime
behaviours account for nearly every difference between the two halves of the matrix, and each was
measured on Node v24.19.0 before the lab was written rather than assumed from documentation.

**URL parsing.** The authority a guard compares against depends on which parser produced it:

| written | `new URL(u).hostname` | `url.parse(u).hostname` | Python `urlparse(u).hostname` |
|---|---|---|---|
| `http://2130706433/` | `127.0.0.1` | `2130706433` | `2130706433` |
| `http://0177.0.0.1/` | `127.0.0.1` | `0177.0.0.1` | `0177.0.0.1` |
| `http://0x7f000001/` | `127.0.0.1` | `0x7f000001` | `0x7f000001` |
| `http://127.1/` | `127.0.0.1` | `127.1` | `127.1` |
| `http://%31%32%37%2e%30%2e%30%2e%31/` | `127.0.0.1` | `` (empty) | `%31%32%37%2e%30%2e%30%2e%31` |
| `http://[::1]/` | `[::1]` | `::1` | `::1` |
| `http://internal.ssrefuse.test./` | `internal.ssrefuse.test.` | same | same |

The WHATWG parser canonicalises the first five; the legacy parser and Python's `urlparse` do not.
A hostname denylist is therefore a different guard depending on which line produced the hostname,
which is what `js-007` and `js-008` hold constant everything else to show. Note also that the
WHATWG parser keeps the brackets on an IPv6 literal, so `[::1]` does not equal a denylist entry
written as `::1`.

**Credentials in the URL.** `fetch('http://host@127.0.0.1/')` throws `TypeError: Request cannot be
constructed from a URL that includes credentials` before any request is sent. `http.get` on the same
URL connects to `127.0.0.1` and sends a Basic auth header. So the userinfo family (`B09`) and the
decoded-delimiter family (`B21`) are exploitable through one Node sink and not the other, with the
guard unchanged. The matrix records those cells as `sink_error`, not as `blocked`, because the
application never refused anything.

**Redirects.** `fetch` follows them unless given `redirect: 'manual'`; `http.get` never follows one.
Python's `requests` follows unless given `allow_redirects=False`. This is why `B13` works against
`py-008` and not against `js-009`, which carry the same prefix allowlist.

**Scheme handlers.** Neither `fetch` nor `http.get` has a `file:` handler -- `fetch` raises
`not implemented... yet...` and `http.get` raises `Protocol "file:" not supported`. The `B17` family
therefore has no positive cell in the JavaScript lab that is not the curl subprocess, and that is a
fact about the sinks rather than about any guard.

## The sink decides more than the guard does, within one language too

The cross-language table is the obvious comparison, and it is not the sharpest one. `py-007` and
`py-017` carry an identical hostname denylist and differ only in the client library, and the
measured rows differ:

| family | `py-007` (requests) | `py-017` (httpx) | `py-018` (curl) |
|---|---|---|---|
| `B27_unicode_authority` | sink error, HTTP 500 | **reached internal** | **reached internal** |
| `B22_gopher_scheme` | blocked | blocked | **reached Redis** |
| `B23_dict_scheme` | blocked | blocked | **reached Memcached** |

`http://127。0。0。1:19001/admin` is written with ideographic full stops. UTS-46 maps them onto ASCII
dots, so the name resolves to loopback, while `urlparse(...).hostname` returns the original
characters and the denylist entry `127.0.0.1` does not match them. Whether that reaches anything is
then decided by the client: requests rejects the URL before sending it, httpx sends it, curl sends
it. The guard is the same line of code in all three routes.

This is the reason the catalog has a scheme axis at all. `gopher://` and `dict://` are what turn an
SSRF into writes against Redis in production, and the only sink in either lab that speaks them is
the curl subprocess -- the one sink a library-level static rule cannot see.

## What the internal service range is for, and what it is not

The testbed runs fifteen services rather than one admin endpoint. The list is drawn from what SSRF
is aimed at in production rather than from a training range: an unauthenticated Docker Engine API on
2375, Elasticsearch on 9200, Consul on 8500, a Spring Boot actuator on 8081, another host inside
RFC 1918, Redis on 6379 and Memcached on 11211, plus the cloud metadata addresses. Each serves one
canary and nothing else.

Two things follow that a single-target testbed cannot show.

**A guard phrased against an address says nothing about a port.** `B24` holds the loopback address
fixed and varies only the port. On every route with no guard, every port in the range answers: no
guard in this corpus distinguishes 2375 from 19001, and the Docker API alone is the difference
between reading a page and executing code on the host.

**Not every metadata service is reachable by a URL alone.** `B30` aims at GCP's
`/computeMetadata/v1/`, Azure's `/metadata/instance` and the IMDSv2 token endpoint. All three need
something an attacker who controls only a URL cannot produce -- `Metadata-Flavor: Google`,
`Metadata: true`, a PUT -- and the fake services enforce exactly that. The requests arrive and come
back without the canary, which is scored `reached_not_disclosed` and is deliberately not a bypass:

- scoring it as a bypass would credit the attacker with a disclosure that did not happen;
- scoring it as blocked would credit the application with a guard it does not have.

It was the cloud's mitigation, and the matrix says so with its own symbol. The same run shows IMDSv1,
ECS task metadata on `169.254.170.2` and Alibaba's `100.100.100.200` answering a plain GET, so the
difference is measured rather than asserted.

## Why a catalog cannot claim completeness, and what it reports instead

There is no finite list of ways to write an address or wrap an authority, so "every payload is
included" is not a claim this project can make. What it can do is be a cross product of named axes
and publish the size of each one, which is a number a reader can check:

| axis | what it varies |
|---|---|
| spelling | the same internal address, written differently |
| target | a different internal service to reach |
| wrapper | the allowlisted name present without being the authority |
| scheme | a handler other than http |
| flow | the request changes destination after the guard ran |

`results/report.md` prints the family and value counts per axis. A payload taken from a public
collection goes into the axis it belongs to as one line in `ssrefuse/harness/payloads.py`; one that
fits no axis is the signal to add an axis rather than to append it somewhere convenient. Families
whose every cell is negative stay in the table, because a measured zero over twenty values is a
result and removing it would turn the table into a list of what happened to work.

## Attribution

A static finding belongs to a variant when it lands inside that variant's `@ssrefuse:begin/end`
span. Shared helpers are marked the same way and declared by the variants that route through them, so a
finding at the sink inside `_fetch_remote` is attributed to both `py-003` and `py-004`, and one
inside `fetchRemote` to both `js-003` and `js-004`. The report prints how many findings were
attributed that way.

This is also why every route in both labs calls its own sink instead of sharing one fetch helper.
The shared helper is the better code and the worse benchmark: with one helper, every static finding
in the lab lands on the same two lines and cannot be attributed to any route. The first draft of the
JavaScript lab was written that way and produced three findings for twenty-three variants, which is
how the problem was noticed.

Findings outside every labelled region are counted and listed. An unattributed finding is neither a
true nor a false positive until someone looks at it, and a pipeline that drops them reports a
precision it did not earn.

## Timing and provenance

The host clock runs at UTC-04:00. Timestamps in `results/` are local to the measuring machine.
Model answers are cached on disk keyed by provider, model, temperature, thinking budget and the
exact prompt text, so re-running the evaluation does not produce different numbers from resampling,
and a changed prompt cannot be scored against answers to the previous one. The budget is in the key
because the same prompt at a different budget is a different measurement, and serving one arm from
the other's cache would collapse the ablation into a single column.

One caveat belongs with that list. Temperature is in the key whether or not the transport sent it:
the opencode transport takes no temperature, so two runs at different `--temperature` values make
the same request and still get separate cache entries. That direction is the safe one -- it buys a
redundant call, not a wrong number -- but a cached answer from that transport is an answer at the
provider's default temperature, which is what `temperature_sent: false` in the results payload
records.
