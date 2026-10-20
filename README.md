# SSReFuse

SSRF detection that fuses static analysis with LLM reasoning, evaluated against a lab that runs
rather than a corpus that is read.

The repository has three parts: a hermetic SSRF testbed, a classified catalog of bypass payloads, and
three detector tiers (sink inventory, taint analysis, LLM judge) scored over one labelled corpus.

## Why the ground truth is dynamic

A rule that reports "SSRF here" is a hypothesis. Whether it holds is settled by sending a request.
So the labels in this project are not the end of the evidence chain. A prober fires 28 payload values
at every route and reads the canary string out of the response body, or out of the target's own access
log when the body is discarded. `corpus/ground-truth.yaml` states which routes are vulnerable; the
prober states which payloads reached an internal target; the evaluator prints both and flags every
disagreement. Where the two differ, either the lab or the catalog is wrong, and the report says so
instead of averaging it away.

## Testbed

Every measurement runs inside an unprivileged network namespace (`unshare -r -n -m`). Inside it:

| address | service |
|---|---|
| `127.0.0.1:19001` | internal admin service holding the canary `SSREFUSE-INTERNAL-ADMIN-SECRET` |
| `169.254.169.254` | fake cloud metadata service returning fabricated credentials |
| `192.88.99.10` | the "public" host the application allowlists, also attacker-controlled, with an open redirect |
| `100.64.0.10` | RFC 6598 shared address space, the range most guards forget |
| `192.88.99.20` | out-of-band canary logging every DNS query and HTTP hit |

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

The result lands in `results/report.md`. Stages run on their own:

```sh
make selftest    # build the sandbox and print the evidence that it is hermetic
make probe       # fire the whole catalog at every variant
make scan        # run the static detectors with their positive control
make report      # score what has been measured
make test        # 47 tests
```

The LLM tier needs an API key:

```sh
export DEEPSEEK_API_KEY=...
.venv/bin/python -m ssrefuse.cli judge --model deepseek-chat --rounds 2
.venv/bin/python -m ssrefuse.cli report
```

Without a key, `--provider mock` exercises the whole pipeline. Every mock answer is labelled, and the
report states that those rows are not measurements.

## Corpus

23 variants in `corpus/labs/flask_ssrf/app.py`, 18 vulnerable and 5 safe. Each variant is one route
with one guard, from nothing at all (`G0`) to a correct one (`G8`: resolve once, classify the address,
connect to that same address, refuse redirects). The five safe routes are the false-positive control
set, and each has to record why it is safe.

Variant boundaries are not stored as line numbers. They are read from `@ssrefuse:begin` markers in the
source, so editing a lab cannot silently invalidate a label. The loader cross-checks both directions
and prints every mismatch.

## Current numbers

Over the 23 Python variants, scored against the declared labels:

| detector | TP | FP | FN | TN | precision | recall |
|---|---|---|---|---|---|---|
| sink inventory | 18 | 4 | 0 | 1 | 0.818 | 1.000 |
| taint, no sanitizers | 15 | 3 | 3 | 2 | 0.833 | 0.833 |
| taint, naive sanitizers | 15 | 3 | 3 | 2 | 0.833 | 0.833 |

The interesting row is the one the table does not have: three variants on which all three detectors
are wrong. `py-012`, `py-014` and `py-023` all have guards of the right shape. `py-014` is correct,
`py-012` is correct within what was measured, and `py-023` blocked both path payloads. Pattern
matching cannot separate a guard that has the right shape from a guard that has an effect, because the
real question is whether the value that was checked is the value that gets fetched. That question is
what the LLM judge is given.

Taint analysis misses `py-003` and `py-004`, where the sink sits in a shared helper, and `py-020`,
where one request stores the URL and another fetches it. Sink inventory catches all 18 and pays for it
on `py-022`, a route whose URL is a module constant.

## Bypass matrix

`results/report.md` carries the full variant-by-family table. Some rows:

- `py-011`, exact hostname allowlist with redirects followed: one family gets through, the redirect.
- `py-013`, resolve and classify then fetch by hostname: only DNS rebinding gets through, and only
  inside a bounded window. The prober retries up to six times and records how many it used.
- `py-007`, denylist over the parsed hostname: 14 families get through, including decimal, octal, hex,
  IPv6, a trailing dot, CGNAT space and a name that resolves internally.
- `py-014`: nothing gets through.

Cells keep four outcomes apart instead of merging them: the application refused the input, the client
raised, the request went out but reached nothing internal, and the request reached an internal target.
Merging the first three is how a bypass matrix comes to overstate a filter.

## Limitations

- Only the Python lab exists. The JavaScript and PHP labs are not written, and CodeQL has not been run.
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
