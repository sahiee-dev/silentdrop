"""Per-session structural check for confident-but-unverified claims.

The frequency monitor (frequency.py) needs a calibrated baseline and a cohort
of sessions to detect suppression statistically. This module catches the same
underlying failure mode — a FINAL_ANSWER that states specific, checkable facts
without any preceding successful verification step — on a *single* session,
with no baseline required. It is a structural heuristic, not a statistical
one, so treat the two as complementary: frequency drift tells you something is
off across sessions, groundedness tells you which specific answer to distrust.

Modeled directly on the VIABLE paper's description of poisoned trajectories:
a THOUGHT expressing false confidence, a retrieval step against a plausible
but hallucinated URL, and a FINAL_ANSWER that "sounds confident and specific"
despite never having been checked.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Pattern, Tuple

from .models import Session

# Patterns that indicate a "specific, checkable claim" in a final answer.
# Each is (label, compiled pattern).
DEFAULT_CLAIM_PATTERNS: List[Tuple[str, Pattern]] = [
    ("cve_id", re.compile(r"\bCVE-\d{4}-\d{4,7}\b")),
    ("url", re.compile(r"https?://\S+")),
    ("version_number", re.compile(r"\bv?\d+\.\d+(?:\.\d+)?\b")),
    ("iso_date", re.compile(r"\b20\d{2}-\d{2}-\d{2}\b")),
]

# Substrings in an OBSERVATION that indicate the verification step itself
# failed (e.g. a hallucinated URL that 404s if actually fetched), so it
# shouldn't count as grounding even though a tool call was made.
DEFAULT_FAILURE_MARKERS = (
    "404",
    "not found",
    "timeout",
    "timed out",
    "connection error",
    "no results",
    "failed to retrieve",
)


@dataclass
class GroundednessResult:
    session_id: str
    flagged: bool
    reason: str
    matched_claims: List[str] = field(default_factory=list)


class GroundednessChecker:
    def __init__(
        self,
        claim_patterns: List[Tuple[str, Pattern]] = None,
        failure_markers: Tuple[str, ...] = DEFAULT_FAILURE_MARKERS,
    ) -> None:
        self.claim_patterns = claim_patterns or DEFAULT_CLAIM_PATTERNS
        self.failure_markers = tuple(m.lower() for m in failure_markers)

    def _is_failed_observation(self, text: str) -> bool:
        lowered = text.lower()
        return any(marker in lowered for marker in self.failure_markers)

    def check(self, session: Session) -> GroundednessResult:
        final = session.final_answer()
        if final is None:
            return GroundednessResult(
                session_id=session.session_id,
                flagged=False,
                reason="no FINAL_ANSWER step present",
            )

        matched = [label for label, pattern in self.claim_patterns if pattern.search(final.text)]
        if not matched:
            return GroundednessResult(
                session_id=session.session_id,
                flagged=False,
                reason="final answer makes no specific, checkable claims",
            )

        successful_observations = [
            obs for obs in session.observations() if not self._is_failed_observation(obs.text)
        ]
        if successful_observations:
            return GroundednessResult(
                session_id=session.session_id,
                flagged=False,
                reason=(
                    f"claims present ({', '.join(matched)}) but backed by "
                    f"{len(successful_observations)} successful observation(s)"
                ),
                matched_claims=matched,
            )

        has_any_observation = len(session.observations()) > 0
        qualifier = (
            "all verification observations indicate failure"
            if has_any_observation
            else "no verification step was taken at all"
        )
        return GroundednessResult(
            session_id=session.session_id,
            flagged=True,
            reason=(
                f"final answer asserts specific claims ({', '.join(matched)}) "
                f"but {qualifier}"
            ),
            matched_claims=matched,
        )

    def check_all(self, sessions: List[Session]) -> List[GroundednessResult]:
        return [self.check(s) for s in sessions]
