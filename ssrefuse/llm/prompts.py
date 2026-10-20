"""Prompts for the LLM judge.

The prompt does not ask "is this vulnerable". It asks the five questions that
decide the answer, in the order that makes the last one cheap, and it requires
each to be answered in the output. The one that matters most is question three:
the expression that was validated and the expression that reaches the sink are
either the same expression or they are not, and nearly every half-correct guard
in the corpus differs exactly there.

The judge is also told it may decline. ``needs_dynamic_test`` plus a filled
``request_more`` is a better answer than a confident guess from an incomplete
slice, and it is what the second round and the prober are for.
"""
from __future__ import annotations

from ssrefuse.harness import payloads as catalog

SYSTEM = (
    "You analyse server-side code for server-side request forgery. You answer "
    "only with a single JSON object matching the requested schema, with no prose "
    "outside it. You never claim a value is attacker-controlled without naming "
    "the expression it came from, and you never claim a guard holds without "
    "saying which expression it constrains."
)

SCHEMA = """{
  "sink_call": "the call that sends the outbound request, as written in the code",
  "destination_expression": "the expression passed to it as the destination",
  "source_chain": ["expression", "...", "ordered from request input to the sink"],
  "attacker_controls_authority": true,
  "validated_expression": "the expression a guard constrains, or null",
  "same_value_validated_and_fetched": true,
  "guard_survives": {
    "redirect": true,
    "second_resolution": true,
    "address_spelling": true,
    "authority_confusion": true,
    "percent_decoding": true
  },
  "verdict": "vulnerable | safe | needs_dynamic_test",
  "confidence": 0.0,
  "bypass_families": ["family ids from the catalog that would work"],
  "reasoning": "two to five sentences, citing line numbers from the slice",
  "unknowns": ["what the slice does not show that you would need"],
  "request_more": {
    "functions": ["module-level function names you want to see"],
    "module_values": ["module-level constant names you want to see"],
    "reason": "why those would change the answer, or empty if nothing would"
  }
}"""


def _family_catalog() -> str:
    lines = []
    for family in catalog.FAMILIES:
        if family.id == catalog.CONTROL_FAMILY or family.instrument:
            continue
        example = family.url_values[0][0] if family.url_values else (
            family.host_values[0][0] if family.host_values else
            family.path_values[0][0] if family.path_values else "")
        lines.append(f"  {family.id}: {family.title}" + (f"  e.g. {example}" if example else ""))
    return "\n".join(lines)


QUESTIONS = """Answer these in order. Each one is a field in the schema.

1. Which call in this slice sends an outbound request, and which expression is
   its destination? Quote the expression.
2. Does that expression derive from request input? Give the chain of
   assignments from the input to the destination, by line number. If it does
   not, say so and stop: there is no SSRF without attacker influence on the
   authority.
3. Which expression, if any, does a guard constrain, and is it the same
   expression that reaches the sink? A guard that validates a copy, a decoded
   version, or a differently parsed form of the value is not a guard on the
   value that is fetched. Be literal about this.
4. If a guard does constrain the fetched value, does it still hold at the
   moment the connection is made? Consider each separately:
   - redirect: does the client follow redirects, so that the checked host can
     send the fetch somewhere else?
   - second_resolution: is the name resolved once for the check and again for
     the connection, so the two can differ?
   - address_spelling: does the check recognise the same address written
     differently, or a name that resolves to it?
   - authority_confusion: can the allowlisted name appear in the URL without
     being the authority, for example as userinfo, in a longer hostname, or in
     a path, query or fragment?
   - percent_decoding: does decoding, or failing to decode, change which host
     the URL points at?
   Answer true when the guard withstands that technique, false when it does not,
   and null when the slice does not say.
5. Verdict. Use "safe" only when the guard constrains the fetched value and
   withstands every technique above. Use "needs_dynamic_test" when the slice
   does not contain what you would need, and fill request_more."""


def build_prompt(slice_text: str, variant_hint: dict, round_number: int = 1,
                 previous: dict | None = None) -> str:
    parts = [
        "## Code slice",
        "",
        "Comments and docstrings have been removed. Line numbers are the real",
        "line numbers of the file. `>>` marks the line a static detector flagged.",
        "",
        "```python",
        slice_text,
        "```",
        "",
        "## What is known from outside the slice",
        "",
        f"- language: {variant_hint.get('lang', 'python')}",
        f"- framework: {variant_hint.get('framework', 'unknown')}",
        f"- the flagged line came from: {variant_hint.get('detector', 'a static detector')}",
    ]
    if variant_hint.get("unresolved_calls"):
        parts.append("- calls the slicer did not expand: "
                     + ", ".join(variant_hint["unresolved_calls"][:12]))
    if variant_hint.get("slice_notes"):
        parts += [f"- {note}" for note in variant_hint["slice_notes"]]

    parts += [
        "",
        "## Bypass families this project measures",
        "",
        "Name the ones that would work against this code, by id.",
        "",
        _family_catalog(),
        "",
        "## Questions",
        "",
        QUESTIONS,
        "",
        "## Output",
        "",
        "One JSON object, this shape, nothing else:",
        "",
        SCHEMA,
    ]
    if round_number > 1 and previous:
        parts += [
            "",
            "## Your previous answer",
            "",
            f"You asked to see more code and gave the verdict "
            f"{previous.get('verdict')!r} with confidence "
            f"{previous.get('confidence')}. The code you asked for has been added",
            "to the slice above. Answer again. If what you asked for is not there,",
            "the notes above say why, and you should decide without it.",
        ]
    return "\n".join(parts)
