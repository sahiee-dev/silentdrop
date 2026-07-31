import pytest

from silentdrop.frequency import DomainFrequencyMonitor
from silentdrop.models import Session, Step


def _session_with_searches(session_id: str, domain: str, n: int) -> Session:
    steps = []
    for i in range(n):
        steps.append(Step(kind="ACTION", text=f"ACTION: search | query: q{i}", action_type="search"))
        steps.append(Step(kind="OBSERVATION", text="results"))
    steps.append(Step(kind="FINAL_ANSWER", text="answer"))
    return Session(session_id=session_id, domain=domain, steps=steps)


def test_calibrate_computes_mean_and_std():
    baseline = [
        _session_with_searches("b0", "security", 2),
        _session_with_searches("b1", "security", 4),
    ]
    monitor = DomainFrequencyMonitor(action_type="search")
    monitor.calibrate(baseline)
    mean, std = monitor._baseline["security"]
    assert mean == 3.0
    assert std == pytest.approx(1.0)


def test_flag_true_when_suppressed():
    baseline = [_session_with_searches(f"b{i}", "security", 3) for i in range(10)]
    monitor = DomainFrequencyMonitor(action_type="search")
    monitor.calibrate(baseline)

    suppressed = _session_with_searches("live", "security", 0)
    result = monitor.flag(suppressed, tau=1.0)
    assert result.flagged
    assert result.z_score < -1.0


def test_flag_false_when_normal():
    baseline = [_session_with_searches(f"b{i}", "security", 3) for i in range(10)]
    monitor = DomainFrequencyMonitor(action_type="search")
    monitor.calibrate(baseline)

    normal = _session_with_searches("live", "security", 3)
    result = monitor.flag(normal, tau=2.0)
    assert not result.flagged


def test_unrelated_domain_unaffected():
    """The core claim of the paper's defense: suppression on one domain
    shouldn't false-positive on a domain that was never suppressed."""
    baseline = [
        *[_session_with_searches(f"sec{i}", "security", 3) for i in range(10)],
        *[_session_with_searches(f"trav{i}", "travel", 2) for i in range(10)],
    ]
    monitor = DomainFrequencyMonitor(action_type="search")
    monitor.calibrate(baseline)

    normal_travel = _session_with_searches("live-travel", "travel", 2)
    result = monitor.flag(normal_travel, tau=2.0)
    assert not result.flagged


def test_score_raises_on_uncalibrated_domain():
    monitor = DomainFrequencyMonitor(action_type="search")
    monitor.calibrate([_session_with_searches("b0", "security", 3)])
    with pytest.raises(ValueError):
        monitor.score(_session_with_searches("live", "travel", 1))


def test_flag_batch_matches_paper_protocol():
    baseline = [_session_with_searches(f"b{i}", "security", 3) for i in range(50)]
    monitor = DomainFrequencyMonitor(action_type="search")
    monitor.calibrate(baseline)

    cohort = [_session_with_searches(f"live{i}", "security", 0) for i in range(50)]
    result = monitor.flag_batch(cohort, tau=2.0)
    assert result.flagged
    assert result.session_id == "batch[50]"


def test_flag_batch_requires_single_domain():
    monitor = DomainFrequencyMonitor(action_type="search")
    monitor.calibrate([_session_with_searches("b0", "security", 3)])
    with pytest.raises(ValueError):
        monitor.flag_batch(
            [
                _session_with_searches("s0", "security", 3),
                _session_with_searches("t0", "travel", 3),
            ]
        )
