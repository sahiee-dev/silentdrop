"""Core data model: a Session is one agent task run, made of ordered Steps."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

STEP_KINDS = ("THOUGHT", "ACTION", "OBSERVATION", "FINAL_ANSWER")


@dataclass
class Step:
    kind: str
    text: str
    action_type: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in STEP_KINDS:
            raise ValueError(f"unknown step kind {self.kind!r}, expected one of {STEP_KINDS}")


@dataclass
class Session:
    session_id: str
    domain: str
    steps: List[Step]

    def action_counts(self) -> Counter:
        return Counter(s.action_type for s in self.steps if s.kind == "ACTION" and s.action_type)

    def final_answer(self) -> Optional[Step]:
        finals = [s for s in self.steps if s.kind == "FINAL_ANSWER"]
        return finals[-1] if finals else None

    def observations(self) -> List[Step]:
        return [s for s in self.steps if s.kind == "OBSERVATION"]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "domain": self.domain,
            "steps": [
                {"kind": s.kind, "text": s.text, "action_type": s.action_type, "meta": s.meta}
                for s in self.steps
            ],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Session":
        return cls(
            session_id=d["session_id"],
            domain=d["domain"],
            steps=[
                Step(
                    kind=s["kind"],
                    text=s["text"],
                    action_type=s.get("action_type"),
                    meta=s.get("meta", {}),
                )
                for s in d["steps"]
            ],
        )
