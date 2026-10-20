# SSReFuse

SSRF detection that fuses static analysis with LLM reasoning, evaluated against a lab that runs
rather than a corpus that is read.

The repository has three parts: a hermetic SSRF testbed, a classified catalog of bypass payloads, and
three detector tiers (sink inventory, taint analysis, LLM judge) scored over one labelled corpus
that spans two languages. The two labs implement the same guard taxonomy, so where a row of the
matrix differs between them, the runtime is the finding.

## Why the ground truth is dynamic

A rule that reports "SSRF here" is a hypothesis. Whether it holds is settled by sending a request.
So the labels in this project are not the end of the evidence chain. A prober fires every applicable
payload value at every route -- 132 values across 34 families -- and reads the canary string out of
the response body, or out of the target's own access log when the body is discarded. `corpus/ground-truth.yaml` states which routes are vulnerable; the
prober states which payloads reached an internal target; the evaluator prints both and flags every
disagreement. Where the two differ, either the lab or the catalog is wrong, and the report says so
instead of averaging it away.

## Testbed

Every measurement runs inside an unprivileged network namespace (`unshare -r -n -m`). Inside it:

| address | service |
|---|---|
| `127.0.0.1:19001` | internal admin service holding the canary `SSREFUSE-INTERNAL-ADMIN-SECRET` |
| `127.0.0.1:2375` | Docker Engine API, the hop that turns a read primitive into host execution |
| `127.0.0.1:9200` | Elasticsearch |
| `127.0.0.1:8500` | Consul KV |
| `127.0.0.1:8081` | Spring Boot actuator |
| `127.0.0.1:6379` | Redis: a line protocol, not HTTP, reachable only by a sink that speaks `gopher://` |
| `127.0.0.1:11211` | Memcached, same |
| `127.0.0.1:19999` | nothing, on purpose: the control that makes "connected" mean something |
| `10.0.0.10` | another host inside RFC 1918, reached by address and by name |
| `169.254.169.254` | cloud metadata: IMDSv1 answers a plain GET, while the GCP, Azure and IMDSv2 paths require a request header and refuse without it |
| `169.254.170.2` | ECS task metadata, which needs no header |
| `100.100.100.200` | Alibaba Cloud metadata |
| `192.88.99.10` | the "public" host the application allowlists, also attacker-controlled, with an open redirect |
| `100.64.0.10` | RFC 6598 shared address space, the range most guards forget |
| `192.88.99.20` | out-of-band canary logging every DNS query and HTTP hit |

The range is drawn from what SSRF is pointed at in production, not from a training exercise. It is
there because an SSRF is rarely the finding: on its own it reads "the server fetched a URL", and the
severity is the next hop. `results/report.md` prints each target next to the escalation it leads to,
and is explicit that the harness measures reaching the service and does **not** perform the hop.

An authoritative DNS server serves the `ssrefuse.test` zone, in which `rebind.ssrefuse.test` answers
with the public address and the loopback address alternately at TTL 0. DNS rebinding happens for real
there; it is not simulated.

Before any measurement, the harness checks two things and refuses to measure if either fails: TCP to
`1.1.1.1:443` must not connect, and `example.com` must not resolve. That is why exercising a metadata
endpoint in this repository never touches a cloud provider.

`192.88.99.0/24` is the public stand-in because Python classifies it `is_global=True`. The RFC 5737
documentation ranges are classified private, so a guard of the form "resolve and reject private
addresses" would reject the allowlisted host and make every guard look stronger than it is. The
192.88.99.0/24 prefix was deprecated by RFC 7526 and belongs to nobody.

## Running it

```sh
make venv        # create .venv, install semgrep and dependencies
make all         # validate corpus -> probe -> scan -> report
```

Or without make: `pip install -r requirements.txt`, or `requirements-lock.txt` for the exact
versions these numbers were measured on.

The Python lab runs on the project venv. The JavaScript lab needs `node` on PATH (built and
measured on v24.19.0) and installs nothing: it uses only the Node standard library, and the router
is written out rather than taken from a package.

The result lands in `results/report.md`. Stages run on their own:

```sh
make selftest    # build the sandbox and print the evidence that it is hermetic
make probe       # fire the whole catalog at every variant
make scan        # run the static detectors with their positive control
make report      # score what has been measured
make test        # 87 tests
```

`make probe --apps flask_ssrf` (or `node_ssrf`) measures one lab on its own.

The LLM tier needs an API key. Put it in `.env`, which is gitignored:

```sh
cp .env.example .env && chmod 600 .env
$EDITOR .env                      # DEEPSEEK_API_KEY=...
make judge                        # both arms of the ablation, then report
```

The ablation holds the model fixed and moves the thinking budget, because
thinking is a request parameter rather than a model name:

```sh
ssrefuse judge --effort none --rounds 2     # the parameter is not sent at all
ssrefuse judge --effort high --rounds 2
ssrefuse report
```

`--effort none` is not `--effort low`: one omits the parameter, the other asks
for a small budget, and conflating them would attribute the provider's default
to this project. The cache is keyed on the effort as well as the prompt, so
neither arm can be served the other's answers. What the thinking cost is
recorded per judgement from the provider's own accounting, because "the
reasoning tier scored higher" and "scored higher at nine times the tokens" are
different findings.

Model ids were checked against the provider changelog on 2026-10-20 and the
previous ones were already stale: `deepseek-chat` and `deepseek-reasoner`
selected non-thinking and thinking mode and were scheduled for retirement on
2026-07-24. Re-check before a submission. `--provider openrouter` and
`--provider openai-compatible` reach the same chat-completions shape elsewhere.

Every command loads `.env` before it runs and prints which variables it set,
by name and never by value. A variable already exported in the shell wins over
the file, so `export DEEPSEEK_API_KEY=...` still overrides it. A blank key is
reported as `empty` rather than treated as present, because a judge that
silently did not run is the one failure this project cannot afford.

Without a key, `--provider mock` exercises the whole pipeline. Every mock answer is labelled, and the
report states that those rows are not measurements.

## Corpus

46 variants, 36 vulnerable and 10 safe, across two labs that implement the same guard taxonomy:

| lab | file | variants | runtime |
|---|---|---|---|
| `flask_ssrf` | `corpus/labs/flask_ssrf/app.py` | 23 (18 vulnerable, 5 safe) | Flask, `requests` / `httpx` / `urllib` / curl |
| `node_ssrf` | `corpus/labs/node_ssrf/app.js` | 23 (18 vulnerable, 5 safe) | Node standard library, `fetch` / `http.get` / curl |

Each variant is one route with one guard, from nothing at all (`G0`) to a correct one (`G8`: resolve
once, classify the address, connect to that same address, refuse redirects). The five safe routes in
each lab are the false-positive control set, and each has to record why it is safe.

Every route calls its own sink rather than sharing a fetch helper. The shared helper is the better
code and the worse benchmark: with one helper, every static finding lands on the same two lines and
cannot be attributed to any route. Each lab keeps exactly one deliberately shared sink, marked as
shared, which is the interprocedural variant.

Variant boundaries are not stored as line numbers. They are read from `@ssrefuse:begin` markers in the
source, so editing a lab cannot silently invalidate a label. The loader cross-checks both directions
and prints every mismatch.

## Current numbers

Over all 46 variants, scored against the declared labels:

| detector | TP | FP | FN | TN | precision | recall |
|---|---|---|---|---|---|---|
| sink inventory | 36 | 8 | 0 | 2 | 0.818 | 1.000 |
| taint, no sanitizers | 31 | 6 | 5 | 4 | 0.838 | 0.861 |
| taint, naive sanitizers | 31 | 6 | 5 | 4 | 0.838 | 0.861 |

Split by language, because a single row would hide which half carries which error:

| detector | Python P / R | JavaScript P / R |
|---|---|---|
| sink inventory | 0.818 / 1.000 | 0.818 / 1.000 |
| taint, no sanitizers | 0.833 / 0.833 | 0.842 / 0.889 |
| taint, naive sanitizers | 0.833 / 0.833 | 0.842 / 0.889 |

Declaring the sanitizers a reviewer would reach for changes nothing in either language. That is the
measurement, not an oversight: `new URL(u).hostname` and `urlparse(u).hostname` sanitise the
hostname, and the value that reaches the sink is the URL.

The LLM judge, run for real against `deepseek-flash` over the same candidate set, with the
thinking budget as the only thing that moves between arms:

| tier | P | R | F1 |
|---|---|---|---|
| sink inventory | 0.818 | 1.000 | 0.900 |
| taint analysis | 0.838 | 0.861 | 0.849 |
| LLM judge, thinking off | 0.882 | 0.833 | 0.857 |
| LLM judge, thinking high | 0.943 | 0.917 | 0.930 |
| **fused cascade, judge-decided cells only** | **0.943** | **1.000** | **0.971** |

Three things in that table are worth more than the ranking.

**Thinking costs twelve times the output tokens for seven points of F1.** 28k output tokens
against 345k, of which 319k is reasoning, and eight times the wall clock. Whether that trade is
worth taking is a decision, and the report prints both halves of it rather than only the half that
flatters the model.

**The one false positive neither arm gives up is the same one: the correct guard.** `py-014` and
`js-015` resolve the hostname once, validate the address, and connect to that address. Both arms
call them vulnerable. A model that cannot be convinced a correct pin-and-connect is correct is a
specific, nameable failure, and it is the failure that matters most for a tool meant to reduce
review load.

**Thinking helped the Python interprocedural slices and not the JavaScript ones.** With thinking
off, the judge declined `py-003`, `py-004`, `js-003` and `js-004`; with it on, it decided the
Python pair and still declined the JavaScript one. That is the documented weakness of the
character-scanner slicer showing up as a measurement rather than as a caveat.

The interesting rows are the ones the table does not have: six variants on which all three static detectors
are wrong, `py-012`, `py-014`, `py-023` and their JavaScript twins. All six have guards of the right
shape; `py-014` and `js-015` are correct, the rest are correct within what was measured. Pattern
matching cannot separate a guard that has the right shape from a guard that has an effect, because
the real question is whether the value that was checked is the value that gets fetched. That
question is what the LLM judge is given.

Taint analysis misses the two interprocedural variants in each lab, and `py-020`, where one request
stores the URL and another fetches it. It catches `js-020`, the same second-order flow, for the
wrong reason: the job id is also request-controlled, so the taint reaches the sink line through the
lookup key rather than through the stored URL. Sink inventory catches all 36 and pays for it on
`py-022` and `js-022`, routes whose URL is a module constant.

## Bypass matrix

`results/report.md` carries the full variant-by-family table. Some rows:

- `py-011`, exact hostname allowlist with redirects followed: one family gets through, the redirect.
- `py-013`, resolve and classify then fetch by hostname: only DNS rebinding gets through, and only
  inside a bounded window. The prober retries up to six times and records how many it used.
- `py-007`, denylist over the parsed hostname: 13 families get through, including decimal, octal, hex,
  IPv6, a trailing dot, CGNAT space and a name that resolves internally.
- `py-014`: nothing gets through.

Cells keep five outcomes apart instead of merging them: the application refused the input, the client
raised, the request went out but reached nothing internal, the request reached an internal target,
and -- the one that is easy to lose -- the request reached the internal service and the service
withheld its secret. Merging the first three is how a bypass matrix comes to overstate a filter.
Merging the last one into either neighbour credits the wrong defender: header-gated cloud metadata
is stopped by the cloud, not by the application, and the matrix gives it its own symbol.

### What the catalog varies, and what it does not claim

"Every payload variant is included" is not a claim this project can make, because there is no finite
list of ways to write an address or wrap an authority. What it does instead is be a cross product of
named axes and publish the size of each:

| axis | what it varies | families | values |
|---|---|---|---|
| spelling | the same internal address, written differently | 9 | 46 |
| target | a different internal service to reach | 5 | 24 |
| wrapper | the allowlisted name present without being the authority | 12 | 44 |
| scheme | a handler other than http | 4 | 9 |
| flow | the request changes destination after the guard ran | 3 | 7 |
| control | must succeed; not an attack | 1 | 2 |

Adding a payload is one line in `ssrefuse/harness/payloads.py`, under the axis it belongs to. One
that fits no axis is the signal to add an axis rather than to append it somewhere convenient.
Families that defeated nothing stay in the table: a measured zero across twenty values is a result.

The catalog was cross-checked against the public SSRF payload collections and the gaps closed:
hosts-file names (`ip6-localhost`, which resolves to `::1` through `/etc/hosts` and no resolver
policy), parser-dependent octal prefixes (`o177.`, `0o177.`, `q177.`), circled letters that UTS-46
folds onto ASCII, backslash authority separators, the scheme written without its slashes, the
encoded path, `ldap://` as a third line-protocol carrier, and a 307 redirect, which preserves the
method where a 302 may not. The sharpest of them is `B32_parser_disagreement`: a single URL that
the guard's parser and the client's parser read as different hosts. It defeats three of the
text-allowlist routes, which no spelling or wrapper family does.

### The sink decides more than the guard does

The cross-language table below is the obvious comparison and not the sharpest one. `py-007` and
`py-017` carry an identical hostname denylist and differ only in the client library:

| family | `py-007` (requests) | `py-017` (httpx) | `py-018` (curl) |
|---|---|---|---|
| authority written with ideographic full stops | sink error | **reached internal** | **reached internal** |
| `gopher://` to Redis | blocked | blocked | **reached Redis** |
| `dict://` to Memcached | blocked | blocked | **reached Memcached** |

`http://127。0。0。1:19001/admin` resolves to loopback because UTS-46 maps those characters onto ASCII
dots, while `urlparse(...).hostname` hands the denylist the original characters. Whether anything is
reached is then the client's decision, not the guard's. And `gopher://` -- the technique that turns
an SSRF into writes against Redis -- works only through the subprocess sink, which is the one sink a
library-level static rule cannot see at all.

### The same guard, two runtimes

The report has a table that pairs variants by guard and injection shape across the two labs and
prints, per language, which families worked only there. Three runtime behaviours produce nearly all
of the difference, each measured on Node v24.19.0 before the lab was written:

- **The parser decides what a hostname denylist is.** `new URL()` canonicalises `2130706433`,
  `0177.0.0.1`, `0x7f000001`, `127.1` and a percent-encoded authority to `127.0.0.1`; the legacy
  `url.parse()` and Python's `urlparse()` return them as written. The same denylist therefore blocks
  five families in one case and none of them in the other. `js-007` and `js-008` hold everything
  else constant to isolate exactly that.
- **`fetch` refuses a URL carrying credentials** and throws before sending anything, so the userinfo
  family is not exploitable through it; `http.get` accepts the same URL and sends Basic auth. Those
  cells are recorded as `sink_error`, never as `blocked`, because the application refused nothing.
- **`fetch` follows redirects by default and `http.get` never does**, which is why the redirect
  family defeats `py-008` and not `js-009`, two routes with the same prefix allowlist.

## Limitations

- Two labs exist, Python and JavaScript. The PHP lab is not written, and CodeQL has not been run.
- The escalation column in the report is written down, not executed. Reaching the Docker API is
  measured; creating a container with the host filesystem mounted is not, and the report says so
  wherever the column appears.
- The JavaScript slicer is a character scanner, not a parser: no JavaScript parser is available
  without a package tree. It is backed by a fixture whose expected output is written down, and
  everything it cannot resolve travels into the prompt, but it is weaker than the Python slicer and
  a construct the scanner has not seen is a construct it may split wrongly.
- No real applications yet. Juice Shop and a CVE-backed corpus are planned, not done.
- The LLM tier is wired and tested through the mock provider, and has no real numbers yet because it
  has not been run against an API key.
- In `fuse_cascade`, a `needs_dynamic_test` answer is settled by the prober. On those cells the verdict
  and the label come from the same measurement, so the report scores the judge-decided subset
  separately. Read that row, not the total.
- The prober reads no source. It is a blackbox engine already, missing only an endpoint-discovery
  stage in front of it.

## Documentation

- `docs/DESIGN.md`: architecture, and why the pipeline is fused instead of handing a repository to a model
- `docs/EVAL-PROTOCOL.md`: how ground truth is established, which controls run, which numbers were measured
- `docs/THREAT-MODEL.md`: STRIDE over the feature "the application fetches a user-supplied URL"
