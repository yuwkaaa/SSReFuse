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
succeed on every variant whose guard permits that host, and the report prints the count: 20 passes, 3
not applicable (two routes take no URL, one sends no request). A run where the control fails
everywhere means the prober is broken, and no negative result in it can be read as a guard holding.

**The detector positive control.** `tests/fixtures/positive_control_python.py` is scanned in the same
semgrep invocation as the corpus. A configuration that reports nothing there is marked unusable and
its numbers are not comparable. This catches a rule file that failed to load, a pattern typo, and a
semgrep upgrade that changed pattern semantics, all of which otherwise produce a confident zero.

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

## Attribution

A static finding belongs to a variant when it lands inside that variant's `@ssrefuse:begin/end`
span. Shared helpers are marked the same way and declared by the variants that route through them, so a
finding at the sink inside `_fetch_remote` is attributed to both `py-003` and `py-004`. The report
prints how many findings were attributed that way.

Findings outside every labelled region are counted and listed. An unattributed finding is neither a
true nor a false positive until someone looks at it, and a pipeline that drops them reports a
precision it did not earn.

## Timing and provenance

The host clock runs at UTC-04:00. Timestamps in `results/` are local to the measuring machine.
Model answers are cached on disk keyed by provider, model, temperature and the exact prompt text, so
re-running the evaluation does not produce different numbers from resampling, and a changed prompt
cannot be scored against answers to the previous one.
