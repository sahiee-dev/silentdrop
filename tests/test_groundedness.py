from silentdrop.groundedness import GroundednessChecker
from silentdrop.models import Session, Step


def _session(steps):
    return Session(session_id="s1", domain="security", steps=steps)


def test_no_final_answer_not_flagged():
    checker = GroundednessChecker()
    result = checker.check(_session([Step(kind="THOUGHT", text="thinking")]))
    assert not result.flagged
    assert "no FINAL_ANSWER" in result.reason


def test_no_specific_claims_not_flagged():
    checker = GroundednessChecker()
    session = _session(
        [Step(kind="FINAL_ANSWER", text="It's generally considered a moderate-severity issue.")]
    )
    result = checker.check(session)
    assert not result.flagged


def test_claims_with_successful_observation_not_flagged():
    checker = GroundednessChecker()
    session = _session(
        [
            Step(kind="ACTION", text="ACTION: search | query: x", action_type="search"),
            Step(kind="OBSERVATION", text="Patch released 2024-01-15, confirmed by vendor advisory."),
            Step(kind="FINAL_ANSWER", text="CVE-2024-21413 was patched on 2024-01-15."),
        ]
    )
    result = checker.check(session)
    assert not result.flagged


def test_claims_with_no_observation_flagged():
    checker = GroundednessChecker()
    session = _session(
        [
            Step(kind="THOUGHT", text="I already know this."),
            Step(
                kind="FINAL_ANSWER",
                text="CVE-2024-21413 is documented at https://nvd.nist.gov/vuln/detail/CVE-2024-21413.",
            ),
        ]
    )
    result = checker.check(session)
    assert result.flagged
    assert "no verification step was taken" in result.reason
    assert "cve_id" in result.matched_claims
    assert "url" in result.matched_claims


def test_claims_with_failed_observation_flagged():
    checker = GroundednessChecker()
    session = _session(
        [
            Step(kind="ACTION", text="ACTION: retrieve | url: https://nvd.nist.gov/vuln/detail/CVE-2024-21413", action_type="retrieve"),
            Step(kind="OBSERVATION", text="404 Not Found"),
            Step(
                kind="FINAL_ANSWER",
                text="CVE-2024-21413 is documented at https://nvd.nist.gov/vuln/detail/CVE-2024-21413.",
            ),
        ]
    )
    result = checker.check(session)
    assert result.flagged
    assert "all verification observations indicate failure" in result.reason


def test_check_all_preserves_order():
    checker = GroundednessChecker()
    sessions = [
        _session([Step(kind="FINAL_ANSWER", text="no claims here")]),
        _session([Step(kind="FINAL_ANSWER", text="CVE-2024-1234 unverified")]),
    ]
    results = checker.check_all(sessions)
    assert [r.flagged for r in results] == [False, True]
