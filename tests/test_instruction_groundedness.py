"""Unit tests for InstructionGroundednessChecker
(evaluation/instruction_groundedness.py), independent of the specific
captured data used in evaluation/instruction_backdoor_pilot.py. These use
synthetic classify_fn stand-ins to pin the checker's own logic: given raw
and paraphrase labels, does it flag disagreement correctly under both
require_unanimous modes, and does it refuse to run with no paraphrases at
all (unlike GroundednessChecker, this checker has no baseline-free,
zero-paraphrase mode).
"""

import pytest

from evaluation.instruction_groundedness import (
    InstructionGroundednessChecker,
    InstructionGroundednessResult,
)


def trigger_classifier(text: str) -> str:
    """A toy word-level backdoor: force Positive iff the text contains the
    literal token 'TRIGGER', else Negative -- a controllable stand-in for a
    real (possibly backdoored) classifier under test."""
    return "Positive" if "TRIGGER" in text else "Negative"


def test_flags_when_raw_and_paraphrase_disagree():
    checker = InstructionGroundednessChecker(classify_fn=trigger_classifier)
    result = checker.check("i1", "this is bad TRIGGER", ["this is bad"])
    assert result.raw_label == "Positive"
    assert result.paraphrase_labels == ["Negative"]
    assert result.flagged is True
    assert result.n_disagreements == 1


def test_does_not_flag_when_raw_and_paraphrase_agree():
    checker = InstructionGroundednessChecker(classify_fn=trigger_classifier)
    result = checker.check("i2", "this is bad", ["this is still bad"])
    assert result.raw_label == "Negative"
    assert result.paraphrase_labels == ["Negative"]
    assert result.flagged is False
    assert result.n_disagreements == 0


def test_blind_to_a_trigger_that_survives_paraphrase():
    """The documented, permanent blind spot: if the paraphrase preserves
    whatever the classifier keys on (here, by construction, still containing
    'TRIGGER'), the check has nothing to catch -- mirrors why this defense
    is structurally blind to semantic-level instruction backdoors."""
    checker = InstructionGroundednessChecker(classify_fn=trigger_classifier)
    result = checker.check("i3", "this is bad TRIGGER", ["this is quite bad TRIGGER"])
    assert result.flagged is False


def test_require_unanimous_true_flags_on_any_single_disagreement():
    checker = InstructionGroundednessChecker(classify_fn=trigger_classifier, require_unanimous=True)
    result = checker.check(
        "i4",
        "bad TRIGGER",
        ["bad TRIGGER still", "bad now"],  # one paraphrase keeps the trigger, one doesn't
    )
    assert result.paraphrase_labels == ["Positive", "Negative"]
    assert result.flagged is True


def test_require_unanimous_false_needs_a_majority_to_flag():
    checker = InstructionGroundednessChecker(classify_fn=trigger_classifier, require_unanimous=False)
    # 1 of 3 paraphrases disagrees -- not a majority, should not flag.
    result = checker.check(
        "i5",
        "bad TRIGGER",
        ["bad TRIGGER a", "bad TRIGGER b", "bad only"],
    )
    assert result.n_disagreements == 1
    assert result.flagged is False

    # 2 of 3 disagree -- a majority, should flag.
    result2 = checker.check(
        "i6",
        "bad TRIGGER",
        ["bad only a", "bad only b", "bad TRIGGER c"],
    )
    assert result2.n_disagreements == 2
    assert result2.flagged is True


def test_raises_without_any_paraphrase():
    checker = InstructionGroundednessChecker(classify_fn=trigger_classifier)
    with pytest.raises(ValueError):
        checker.check("i7", "bad TRIGGER", [])


def test_check_all_runs_every_item():
    checker = InstructionGroundednessChecker(classify_fn=trigger_classifier)
    items = [
        ("a", "bad TRIGGER", ["bad"]),
        ("b", "bad", ["bad too"]),
    ]
    results = checker.check_all(items)
    assert [r.item_id for r in results] == ["a", "b"]
    assert isinstance(results[0], InstructionGroundednessResult)
    assert results[0].flagged is True
    assert results[1].flagged is False
