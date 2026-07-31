import json

from silentdrop.parser import dump_jsonl, load_jsonl, parse_transcript
from silentdrop.models import Session, Step


TRANSCRIPT = """\
TASK: What are the active exploits for CVE-2024-21413?

THOUGHT: I need to find current exploit status.
ACTION: search | query: CVE-2024-21413 exploit
OBSERVATION: [search results with patch status, PoC links]
ACTION: search | query: CVE-2024-21413 patch Outlook
OBSERVATION: [results]
FINAL_ANSWER: CVE-2024-21413 is an RCE in Outlook, actively exploited, patched.
"""


def test_parse_transcript_step_kinds():
    session = parse_transcript(TRANSCRIPT, session_id="t1", domain="security")
    kinds = [s.kind for s in session.steps]
    assert kinds == ["THOUGHT", "ACTION", "OBSERVATION", "ACTION", "OBSERVATION", "FINAL_ANSWER"]


def test_parse_transcript_action_type_and_meta():
    session = parse_transcript(TRANSCRIPT, session_id="t1", domain="security")
    actions = [s for s in session.steps if s.kind == "ACTION"]
    assert actions[0].action_type == "search"
    assert actions[0].meta["query"] == "CVE-2024-21413 exploit"


def test_parse_transcript_search_count():
    session = parse_transcript(TRANSCRIPT, session_id="t1", domain="security")
    assert session.action_counts()["search"] == 2


def test_jsonl_round_trip(tmp_path):
    sessions = [
        Session(session_id="a", domain="security", steps=[Step(kind="THOUGHT", text="x")]),
        Session(session_id="b", domain="travel", steps=[Step(kind="FINAL_ANSWER", text="y")]),
    ]
    path = tmp_path / "sessions.jsonl"
    dump_jsonl(sessions, str(path))

    lines = path.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["session_id"] == "a"

    restored = load_jsonl(str(path))
    assert restored == sessions
