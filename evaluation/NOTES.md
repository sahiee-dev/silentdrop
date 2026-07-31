# Evasion sweep v1 — analysis

Raw data: `results_v1.csv` (12 sessions per cohort, same clean baseline as
`examples/clean_sessions.jsonl`: security-domain search count mean=1.93,
std=0.77).

## Finding 1: GroundednessChecker v1 collapses at budget=1, both decoy modes

Recall goes 1.000 → 0.000 the instant a single successful decoy observation
exists in the session, regardless of whether that decoy is topically related
to the claim or not. This is exactly the design gap it looks like on
inspection of `groundedness.py`: the check is "does *any* successful
observation exist", not "does a successful observation actually address the
claim". A single irrelevant decoy search is indistinguishable from real
verification to this checker. Not a subtle result — a total, immediate
failure mode.

## Finding 2: DomainFrequencyMonitor also collapses at budget=1

At budget=0 (no decoys) mean z=-2.50, flagged at every tau tested. At
budget=1, mean z=-1.21 — already above even the most sensitive threshold
tested (tau=1.5). The reason is arithmetic, not a bug: with baseline
mean≈1.93 and std≈0.77, an attacker doesn't need to match the mean, only get
within `tau*std` of it. At tau=1.5 that's a window of ~1.15 searches around
the mean — one decoy (bringing count 0→1) already lands inside it. This is a
direct, mechanical consequence of the z-score formula given a baseline with
this much spread, not something that needed a large evasion budget to find.

**Caveat on threshold choice:** the VIABLE paper's own defense section
reports tau=2.0 calibrated against 50 real sessions, not 12 synthetic ones,
and found much stronger separation (98% recall / <2% FPR) — likely because
real per-session search-count variance is different from this hand-built
synthetic baseline. This sweep is not a claim that the paper's actual
calibrated defense is this fragile in deployment; it's a claim that *given
this baseline's variance*, a small, fixed decoy budget is sufficient to
evade it, which is the mechanism an adaptive attacker would exploit
regardless of the exact numbers. The qualitative point (a fixed small
decoy budget can normalize a z-score if baseline variance is non-trivial)
generalizes; the exact "budget=1 suffices" number is specific to this
synthetic baseline's std and should be re-measured against any real
deployment's own baseline variance before being treated as a deployment
recommendation.

## What this motivates

The frequency monitor's fragility here is inherent to any single-signal
z-score approach — no code fix removes it, only a better baseline (larger,
lower-variance, ideally with a robustness margin) or a second independent
signal reduces the exposure. That's out of scope for a code change in this
repo.

The groundedness checker's fragility, on the other hand, is exactly a code
gap: it never checks relevance between the claim and the observation. That's
the next task — a v2 checker that requires the successful observation to
actually share checkable substance (e.g. the exact CVE ID / URL) with the
claim, and re-running this same sweep against it.
