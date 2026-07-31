"""Parsers for agent transcripts: JSONL (primary) and a plaintext THOUGHT/ACTION/
OBSERVATION/FINAL_ANSWER format (matching the trajectory format used to train and
evaluate VIABLE-style agents).
"""

from __future__ import annotations

import json
import re
from typing import Iterable, Iterator, List, Optional

from .models import Session, Step

_ACTION_LINE = re.compile(r"^ACTION:\s*(?P<type>[^|]+?)\s*(\|\s*(?P<rest>.*))?$")
_STEP_PREFIXES = ("THOUGHT:", "ACTION:", "OBSERVATION:", "FINAL_ANSWER:")


def load_jsonl(path: str) -> List[Session]:
    sessions = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            sessions.append(Session.from_dict(json.loads(line)))
    return sessions


def dump_jsonl(sessions: Iterable[Session], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for session in sessions:
            fh.write(json.dumps(session.to_dict()) + "\n")


def _parse_action_line(text: str) -> Step:
    match = _ACTION_LINE.match(text)
    if not match:
        return Step(kind="ACTION", text=text)
    action_type = match.group("type").strip()
    rest = match.group("rest") or ""
    meta = {}
    for part in rest.split("|"):
        part = part.strip()
        if ":" in part:
            key, _, value = part.partition(":")
            meta[key.strip()] = value.strip()
    return Step(kind="ACTION", text=text, action_type=action_type, meta=meta)


def parse_transcript(text: str, session_id: str, domain: str) -> Session:
    """Parse a single plaintext transcript (one session) in THOUGHT/ACTION/
    OBSERVATION/FINAL_ANSWER format into a Session. Lines that don't start with
    a known step prefix are treated as a continuation of the previous step.
    """
    steps: List[Step] = []
    current_kind: Optional[str] = None
    current_lines: List[str] = []

    def flush() -> None:
        if current_kind is None:
            return
        body = "\n".join(current_lines).strip()
        if current_kind == "ACTION":
            steps.append(_parse_action_line(f"ACTION: {body}"))
        else:
            steps.append(Step(kind=current_kind, text=body))

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("TASK:"):
            continue
        matched_prefix = next((p for p in _STEP_PREFIXES if line.startswith(p)), None)
        if matched_prefix:
            flush()
            current_kind = matched_prefix[:-1]
            current_lines = [line[len(matched_prefix):].strip()]
        elif current_kind is not None:
            current_lines.append(line)
    flush()

    return Session(session_id=session_id, domain=domain, steps=steps)


def parse_transcript_file(path: str, domain: str) -> Session:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    return parse_transcript(text, session_id=path, domain=domain)
