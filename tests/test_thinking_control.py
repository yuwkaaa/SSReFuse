"""The control on the ablation's own axis.

The ablation holds the model fixed and moves the thinking budget, so its whole
claim rests on the two arms having actually run at different budgets. Nothing
in the verdict columns shows whether they did: an arm labelled `off` that
thought anyway returns a complete, plausible table. The provider's token
accounting is the evidence, and this is the check that reads it.

The check is here because the claim was in the code as a comment for five days
without any code behind it -- `client.py` said the run asserted zero reasoning
tokens at `off`, and the only reader of that count printed it when it was
non-zero, which made the one observation that would disprove the arm look like
an ordinary progress line.
"""
from ssrefuse.llm.client import THINKING_CLAIM, thinking_control


def test_the_off_arm_passes_when_it_spent_nothing():
    result = thinking_control("off", 0, usage_reported=True)
    assert result["status"] == "pass"
    assert result["reasoning_tokens"] == 0


def test_the_off_arm_fails_when_it_thought_anyway():
    """The arm this check exists for. Without it the run prints
    `reasoning tokens at effort=off: 412` and carries on."""
    result = thinking_control("off", 412, usage_reported=True)
    assert result["status"] == "FAILED"
    assert "412" in result["detail"]


def test_the_thinking_arm_fails_when_it_did_not_think():
    """The other leg, and the one easy to forget. If `high` spent no reasoning
    tokens then both arms ran at the same budget and the ablation is one arm
    measured twice -- the same failure, in the other direction."""
    result = thinking_control("high", 0, usage_reported=True)
    assert result["status"] == "FAILED"


def test_the_thinking_arm_passes_when_it_thought():
    assert thinking_control("high", 319095, usage_reported=True)["status"] == "pass"


def test_none_claims_nothing_so_there_is_nothing_to_fail():
    """`none` sends no parameter and takes the provider's default, which was
    measured to be thinking ON. Either count is consistent with that, so
    pretending to check it would be the dishonest outcome."""
    for tokens in (0, 143):
        result = thinking_control("none", tokens, usage_reported=True)
        assert result["status"] == "no_claim"
    assert "none" not in THINKING_CLAIM


def test_an_absent_accounting_is_not_checked_rather_than_passed():
    """The case the agent transport creates. Reading a missing count as zero
    would hand every opencode arm a passing `off` control it never earned."""
    result = thinking_control("off", 0, usage_reported=False)
    assert result["status"] == "not_checked"
    assert result["reasoning_tokens"] is None, "an absence rendered as a zero"
    assert "not zero" in result["detail"]


def test_an_absent_accounting_cannot_fail_a_thinking_arm_either():
    """Same rule in the other direction: without usage, `high` is unverified,
    not refuted. A transport limitation must not be reported as the arm's
    failure."""
    assert thinking_control("high", 0, usage_reported=False)["status"] == "not_checked"


def test_every_arm_that_makes_a_claim_has_one_recorded():
    """The claim table and the effort list have to stay in step, or a new
    effort value arrives with no control and silently gets `no_claim`."""
    from ssrefuse.llm.client import REASONING_EFFORTS
    assert set(THINKING_CLAIM) == set(REASONING_EFFORTS) - {"none"}


# --- reading the count the control depends on ------------------------------

def test_a_real_zero_is_not_stepped_over():
    """The bug this extractor was written to avoid. `a or b or 0` skips a
    falsy value and keeps looking, so a provider that correctly reports zero
    reasoning tokens gets read as "no count here" -- at `off`, which is the
    one arm where zero is the expected answer and the value under test."""
    from ssrefuse.llm.client import token_usage
    counts = token_usage({"prompt_tokens": 0, "completion_tokens": 0,
                          "completion_tokens_details": {"reasoning_tokens": 0}})
    assert counts["found"] is True, "a block of honest zeros read as no block"
    assert (counts["input"], counts["output"], counts["reasoning"]) == (0, 0, 0)


def test_an_absent_block_is_distinguishable_from_a_block_of_zeros():
    from ssrefuse.llm.client import token_usage
    assert token_usage({})["found"] is False
    assert token_usage(None)["found"] is False


def test_the_other_vendors_spellings_are_read_too():
    """`openai-compatible` points wherever it is configured, and a proxy is
    free to answer in Anthropic's or Gemini's shape. Reading only OpenAI's
    keys would drop the accounting without saying it had."""
    from ssrefuse.llm.client import token_usage
    anthropic = token_usage({"input_tokens": 11, "output_tokens": 7})
    assert (anthropic["input"], anthropic["output"], anthropic["found"]) == (11, 7, True)
    gemini = token_usage({"promptTokenCount": 11, "candidatesTokenCount": 7,
                          "thoughtsTokenCount": 3})
    assert (gemini["input"], gemini["output"], gemini["reasoning"]) == (11, 7, 3)


def test_a_nested_detail_dict_is_searched_for_the_reasoning_count():
    from ssrefuse.llm.client import token_usage
    assert token_usage({"completion_tokens": 9,
                        "completion_tokens_details": {"reasoning_tokens": 300}}
                       )["reasoning"] == 300


def test_an_unparsable_count_does_not_crash_the_run():
    from ssrefuse.llm.client import token_usage
    assert token_usage({"prompt_tokens": "lots"})["found"] is False
