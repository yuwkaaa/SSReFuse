# Real-world corpus

Targets taken from published CVEs, kept apart from `corpus/labs/` because the
two answer different questions.

`corpus/labs/` is written here, after the fact, against a guard taxonomy. Every
variant has a label a prober reproduced, so precision and recall mean something
over it. What it cannot tell you is whether a detector works on code nobody
wrote for it.

This directory is the other half, and its value is a property of its dates. A
model may have read a 2024 CVE and its patch during training; it cannot have
read one published after its cutoff. Running the same detector, the same prompt
and the same model over both halves separates "the method found it" from "the
model remembered it" -- which is the question a benchmark on public CVEs cannot
answer on its own.

## Layout

    cve2026/manifest.csv      the index: one row per target
    cve2026/<CVE>.yaml        per-target metadata, quoted from the CVE record
    _src/                     checked-out vulnerable sources, gitignored

`_src/` does not exist in a fresh clone and is created on demand. The whole
path is ignored on purpose, with no `.gitkeep` exception: the sources are
large, they are someone else's code, and a benchmark that vendored vulnerable
copies of other people's software into its own history is a benchmark nobody
wants to clone. Ignoring the directory rather than its contents also means a
stray file dropped in there cannot be staged by accident. The YAML files carry
what is needed to fetch an exact version.

## Where the data comes from

Every version range and score in the YAML files is quoted from that CVE's own
record at `cveawg.mitre.org/api/cve/<id>`, with the assigning CNA named. Not
from a vulnerability aggregator and not from a vendor blog: both were checked
against the record while this list was built, and one disagreed -- see the
`disputed` note on CVE-2026-96652.

Anything not in the CVE record is marked as such. "Chains to RCE" is a claim
about two bugs together, and where the record does not say it, the YAML says
who did.

## Running them

Nothing here is probed yet. These targets are not in `corpus/ground-truth.yaml`
and no number in `results/` comes from them, so a reader can tell the measured
corpus from the planned one without reading the code.
