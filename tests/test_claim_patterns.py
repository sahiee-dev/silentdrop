"""Regression tests for DEFAULT_CLAIM_PATTERNS, generated from
evaluation/claim_pattern_ablation.py's case list. If one of these starts
failing, the regex behavior changed — update the ablation doc, don't just
silence the test.
"""

import pytest

from evaluation.claim_pattern_ablation import CASES
from silentdrop.groundedness import DEFAULT_CLAIM_PATTERNS

PATTERNS = dict(DEFAULT_CLAIM_PATTERNS)


@pytest.mark.parametrize("label,text,expect_match,note", CASES)
def test_claim_pattern_case(label, text, expect_match, note):
    actual = bool(PATTERNS[label].search(text))
    assert actual == expect_match, f"{label} on {text!r}: expected {expect_match}, got {actual} ({note})"
