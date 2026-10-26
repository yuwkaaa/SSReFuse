# Design

## The question the architecture answers

Static analysis of SSRF runs into one wall, and it is not reachability. Finding that a request
parameter reaches `requests.get` is a dataflow problem that taint analysis already solves. The hard
part is the next question: the code does validate the URL, so does the validation constrain the value
that gets fetched, and does it still hold at the moment the socket opens?

Three variants in the corpus make that concrete. `py-013` resolves the hostname, rejects non-global
addresses, then fetches by hostname. `py-014` resolves the hostname, rejects non-global addresses,
then connects to the address it validated. The two functions differ by one line. One is exploitable
through DNS rebinding and one is not, and no pattern over the syntax separates them, because the
difference is which value the connection uses. `py-021` is worse: the guard is correct and it is
applied to a decoded copy of a URL whose raw form points somewhere else.

So the pipeline is split by what each stage is good at.

| stage | job | why not the next stage |
|---|---|---|
| sink inventory (semgrep) | find every outbound request sink | cannot say if input reaches it |
| taint analysis (semgrep) | find the ones input reaches | cannot say if a guard is effective |
| LLM judge | decide whether the checked value is the fetched value | answers can be wrong, and are |
| prober | settle it by sending the request | needs a running app and a target |

## Slicing

A model handed a 450-line file spends its attention locating the sink. A model handed the sink, the
function around it, the helpers that function calls, and the module constants those helpers compare
against has nothing left to do but the reasoning. `ssrefuse/slicing.py` builds that slice from the
Python AST: enclosing function, transitively called module-level functions up to a depth, module
assignments referenced by any included code, and the imports. `slice_source` dispatches on the file
extension and raises on one it has no slicer for, so a language added to the corpus cannot quietly
fall through to the Python parser and come back as a fixed-size window.

`ssrefuse/slicing_js.py` produces the same shape for JavaScript without a parser, because adding one
costs a dependency tree that the results would then partly be about. One character scan classifies every position as code, comment, string, template
or regex, and both consumers read it: the comment stripper, and the bracket counter that finds
top-level statement boundaries. The weakness of a scanner against a parser is handled by making it
visible rather than by assuming it away. The one genuinely ambiguous construct in JavaScript
lexing -- regex literal against division -- is resolved with the previous-token rule, stated in the
module rather than buried. And the scan has a control: `tests/fixtures/js_scanner_control.js` holds
the constructs it has to get right and the test asserts counts read off that fixture by hand, since
a wrong statement count looks exactly like a right one.

Three properties of the slice are load-bearing.

It removes comments and docstrings. The lab sources are documented, and the documentation says which
route is vulnerable and which technique defeats it. Benchmarks assembled from annotated code have
flattered LLM detectors for exactly this reason. `tests/test_slicing.py` generates its leakage check
from the lab's own prose, so adding a comment to the lab cannot silently reintroduce the problem.
Line numbers survive stripping: a removed line becomes empty rather than disappearing, so a finding
at line N still points at line N on disk.

It records what it could not expand. Calls into other modules are listed in the prompt, and the judge
is told it may answer `needs_dynamic_test` instead of guessing.

It carries the values a guard compares against. A denylist or an allowlist is a module-level
constant in both labs, and a judgement about a guard made without the contents of the list it
consults is a judgement about the shape of the code. Both slicers pull in every module value any
included code refers to, including values referenced only from inside a template substitution,
which is why the JavaScript scan classifies `${...}` as code rather than as string.

## Letting the judge ask back

The published LLM-assisted SSRF detectors prompt once. This one allows a second round: the output
schema has a `request_more` field, and when the judge answers `needs_dynamic_test` while naming
functions or constants it wants, the slicer widens the slice and the question is asked again. Rounds
are recorded per location, so the cost of the loop and the answers it changed are both reportable.

That loop is the mechanism behind what looks like intelligence in an interactive agent. Nothing about
it requires a vector store. Retrieval here is static slicing over one file, and the bypass catalog
that goes into the prompt is 20 families of text.

## Keeping the fusion from grading itself

`fuse_cascade` sends what the judge declines to decide to the prober. On a lab where the prober also
defines the ground truth, scoring those cells against those labels proves nothing. The strategy
table therefore prints two rows for the cascade: one over all variants, one restricted to the
variants the judge decided by itself. The second row is the one that says something about the model.

## Verdicts stay separate

The prober distinguishes six outcomes, and the matrix keeps them apart:

- `reached_internal`, the only one that counts as a bypass
- `oob_confirmed`, the out-of-band canary fired
- `reached_benign`, the control payload reached the allowlisted partner
- `blocked`, the application refused the input, with its reason
- `sink_error`, the fetch was attempted and failed in the client
- `no_internal_contact`, the fetch happened and went somewhere that is not internal

Folding the last three into "not vulnerable" is how a bypass matrix comes to overstate a filter. A
payload that failed because nothing was listening on IPv6 loopback says nothing about the guard, and
the corpus contains that exact case: `py-006` with `[::1]` was a connection failure until the testbed
grew a dual-stack listener, at which point the guard turned out not to stop it.

## The blackbox path

`ssrefuse/harness/probe.py` never reads application source. It builds HTTP requests from the entry
spec, sends them, and classifies what came back using the canaries and the target access logs. Moving
to blackbox needs an endpoint-discovery stage in front of it and a mode that runs without labels;
the measurement engine is already source-agnostic.

## Layout

```
ssrefuse/
  testbed_spec.py        addresses, ports, DNS zone, canary markers
  corpus.py              ground truth loading, marker scanning, attribution
  slicing.py             AST slicing, annotation stripping, language dispatch
  slicing_js.py          JavaScript scanner: lexing, statement bounds, slicing
  harness/
    sandbox.py           builds the namespace, runs one job inside it
    inside.py            namespace setup, isolation controls, job dispatch
    services.py          DNS, internal targets, OOB canary, access log
    payloads.py          bypass family catalog
    probe.py             lab lifecycle, request building, verdict classification
  detectors/
    base.py              Candidate and DetectorRun, with control accounting
    semgrep_runner.py    semgrep invocation with the positive control
    llm_judge.py         slice, ask, widen, parse
    fuse.py              strategy comparison
  evaluation/
    dynamic.py           bypass matrix, label confirmation, declared vs measured
    static.py            TP/FP/FN/TN, unattributed accounting
  llm/                   client, cache, prompts
  reporting/tables.py    markdown tables
rules/semgrep/           three detector tiers, one rule file per language
corpus/                  labs, ground truth, static-only fixtures
tests/                   87 tests, including the sandbox isolation proof
                         and the JavaScript scanner control
```
