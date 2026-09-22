"""A groundedness-style defense for instruction backdoor attacks (Zhang et
al., "Instruction Backdoor Attacks Against Customized LLMs", USENIX Security
2024) -- see docs/instruction_backdoor_pilot.md for the full write-up and a
worked pilot using this exact class.

`silentdrop.GroundednessChecker` doesn't apply to that paper's threat model
directly: it flags a multi-turn agent's FINAL_ANSWER when no successful
OBSERVATION backs it up, and a single-turn "classify this text" task has
neither a FINAL_ANSWER nor an OBSERVATION to check. What carries over is the
underlying idea, restated for this setting:

    GroundednessChecker: don't count a verification step as grounding just
    because it exists -- require it to actually address the claim (v2:
    `require_relevance`), not just be *some* successful observation.

    InstructionGroundednessChecker: don't count a classification as
    trustworthy just because a model produced it -- require it to survive
    an independent, meaning-preserving re-check, not just re-derive the
    same answer from the same surface form.

Mechanism: classify the input, classify an independently-produced
paraphrase of it that preserves meaning but changes surface form, and flag
disagreement. A word-level trigger (a specific token) or syntax-level
trigger (a sentence structure) is a surface property that a real paraphrase
normally destroys, so disagreement is diagnostic. A semantic-level trigger
(a topic or scenario) is a meaning-level property that a *faithful*
paraphrase, by construction, preserves -- so this check is structurally
blind to it, by the same logic that makes GroundednessChecker v2 blind to a
decoy that echoes the claim's own entities. That is a known, permanent
limitation of this specific mechanism, not a bug to be tuned away: closing
it needs a different kind of defense (e.g. Zhang et al.'s own
"sentence-level intent analysis", which reads the classifier's *instructions*
for suspicious conditional logic instead of probing its behavior on inputs).

The paraphrase(s) must come from a party the attacker doesn't control -- if
the same compromised classify_fn were used to *generate* its own
paraphrases, a sufficiently capable backdoor could simply preserve its own
trigger while paraphrasing, defeating the check by construction. This
module treats paraphrase generation as the caller's responsibility for
exactly that reason: pass in paraphrases from a separate, trusted process.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Tuple


@dataclass
class InstructionGroundednessResult:
    item_id: str
    raw_label: str
    paraphrase_labels: List[str]
    flagged: bool
    reason: str

    @property
    def n_disagreements(self) -> int:
        return sum(1 for label in self.paraphrase_labels if label != self.raw_label)


class InstructionGroundednessChecker:
    """
    classify_fn: the classifier under test, called with one piece of text
        and returning its label. This is the thing that might be
        backdoored; the checker treats it as an opaque black box and never
        inspects its instructions or internals.

    require_unanimous: when True (default -- "v1", mirroring
        GroundednessChecker's own v1/v2 naming), ANY single disagreeing
        paraphrase flags the item: conservative, catches a trigger that
        only sometimes survives paraphrasing, at the cost of being more
        sensitive to a paraphrase that happens to be genuinely ambiguous.
        When False ("v2"), a strict majority of paraphrases must disagree
        to flag -- fewer false positives from one unlucky paraphrase, at
        the cost of needing more than one paraphrase per item and being
        more tolerant of a trigger that survives most, but not all, of
        them.
    """

    def __init__(
        self,
        classify_fn: Callable[[str], str],
        require_unanimous: bool = True,
    ) -> None:
        self.classify_fn = classify_fn
        self.require_unanimous = require_unanimous

    def check(self, item_id: str, text: str, paraphrases: List[str]) -> InstructionGroundednessResult:
        if not paraphrases:
            raise ValueError(
                "check() needs at least one independently-produced paraphrase "
                "to compare against -- this checker has no baseline-free "
                "single-example mode, unlike GroundednessChecker"
            )

        raw_label = self.classify_fn(text)
        paraphrase_labels = [self.classify_fn(p) for p in paraphrases]
        n_disagreements = sum(1 for label in paraphrase_labels if label != raw_label)

        if self.require_unanimous:
            flagged = n_disagreements > 0
        else:
            flagged = n_disagreements > len(paraphrase_labels) / 2

        if flagged:
            reason = (
                f"label {raw_label!r} on the raw input disagreed with "
                f"{n_disagreements}/{len(paraphrase_labels)} independent "
                f"paraphrase(s) -- may depend on surface form rather than content"
            )
        else:
            reason = (
                f"label {raw_label!r} held across all {len(paraphrase_labels)} "
                f"independent paraphrase(s)"
            )

        return InstructionGroundednessResult(
            item_id=item_id,
            raw_label=raw_label,
            paraphrase_labels=paraphrase_labels,
            flagged=flagged,
            reason=reason,
        )

    def check_all(
        self, items: List[Tuple[str, str, List[str]]]
    ) -> List[InstructionGroundednessResult]:
        """items: list of (item_id, text, paraphrases)."""
        return [self.check(item_id, text, paraphrases) for item_id, text, paraphrases in items]
