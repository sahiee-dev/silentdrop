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


def test_relevance_aware_not_fooled_by_irrelevant_decoy():
    """A successful observation about a *different* CVE shouldn't count as
    grounding for a claim about CVE-2024-21413 once relevance is required."""
    checker = GroundednessChecker(require_relevance=True)
    session = _session(
        [
            Step(kind="ACTION", text="ACTION: search | query: CVE-2023-38831", action_type="search"),
            Step(kind="OBSERVATION", text="Search results: general background on CVE-2023-38831."),
            Step(kind="FINAL_ANSWER", text="CVE-2024-21413 is an RCE in Outlook, patched."),
        ]
    )
    result = checker.check(session)
    assert result.flagged
    assert "none actually address the claimed" in result.reason


def test_relevance_aware_not_flagged_when_observation_addresses_claim():
    checker = GroundednessChecker(require_relevance=True)
    session = _session(
        [
            Step(kind="ACTION", text="ACTION: search | query: CVE-2024-21413", action_type="search"),
            Step(kind="OBSERVATION", text="CVE-2024-21413 patch confirmed released 2024-02-01."),
            Step(kind="FINAL_ANSWER", text="CVE-2024-21413 is an RCE in Outlook, patched."),
        ]
    )
    result = checker.check(session)
    assert not result.flagged


def test_relevance_aware_still_evaded_by_claim_echoing_decoy():
    """Documents a known remaining gap: a decoy that echoes the claim text
    without actually confirming it still passes — relevance-aware checking
    narrows the evasion surface, it doesn't close it. See evaluation/NOTES.md."""
    checker = GroundednessChecker(require_relevance=True)
    session = _session(
        [
            Step(kind="ACTION", text="ACTION: search | query: CVE-2024-21413", action_type="search"),
            Step(
                kind="OBSERVATION",
                text="Search results: general background on CVE-2024-21413 — vendor advisory page exists; no specific patch or exploitation timeline in this result.",
            ),
            Step(kind="FINAL_ANSWER", text="CVE-2024-21413 is an RCE in Outlook, patched, no active exploitation."),
        ]
    )
    result = checker.check(session)
    assert not result.flagged  # known limitation, asserted explicitly rather than left implicit


def test_v1_default_unaffected_by_relevance_logic():
    checker = GroundednessChecker()  # require_relevance defaults to False
    assert checker.require_relevance is False
