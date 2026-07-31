from silentdrop.models import Session, Step


def test_action_counts():
    session = Session(
        session_id="s1",
        domain="security",
        steps=[
            Step(kind="THOUGHT", text="thinking"),
            Step(kind="ACTION", text="ACTION: search | query: x", action_type="search"),
            Step(kind="OBSERVATION", text="results"),
            Step(kind="ACTION", text="ACTION: search | query: y", action_type="search"),
            Step(kind="OBSERVATION", text="results"),
            Step(kind="ACTION", text="ACTION: retrieve | url: z", action_type="retrieve"),
            Step(kind="OBSERVATION", text="results"),
            Step(kind="FINAL_ANSWER", text="done"),
        ],
    )
    counts = session.action_counts()
    assert counts["search"] == 2
    assert counts["retrieve"] == 1


def test_final_answer_returns_last_one():
    session = Session(
        session_id="s1",
        domain="security",
        steps=[
            Step(kind="FINAL_ANSWER", text="first draft"),
            Step(kind="FINAL_ANSWER", text="final"),
        ],
    )
    assert session.final_answer().text == "final"


def test_final_answer_none_when_absent():
    session = Session(session_id="s1", domain="security", steps=[Step(kind="THOUGHT", text="x")])
    assert session.final_answer() is None


def test_round_trip_dict():
    session = Session(
        session_id="s1",
        domain="security",
        steps=[Step(kind="ACTION", text="ACTION: search | query: x", action_type="search", meta={"query": "x"})],
    )
    restored = Session.from_dict(session.to_dict())
    assert restored == session
