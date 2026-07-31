# Roadmap

This file is the source of truth for what's in progress and what's next —
read it first before picking up work.

## Shipped (v0.1.0)

- `DomainFrequencyMonitor` — per-domain action-frequency z-score drift detector
- `GroundednessChecker` — flags confident claims with no successful verification step
- JSONL + plaintext transcript parsing
- CLI (`silentdrop scan`)
- 21 passing tests
- Synthetic example transcripts (`examples/`)
- Public repo: https://github.com/sahiee-dev/silentdrop

## In progress: adaptive-evasion study

Both papers this project draws on flag the same open problem: what happens
when the attacker *knows* a behavioral monitor is watching and adapts —
specifically, injecting "decoy" verification calls to stay under the
statistical threshold without actually verifying anything? Nobody has put a
number on that here. That's the gap this phase closes.

Plan (see TaskList for live status — tasks 10-16):

1. **Adaptive-evasion session generator** — extend the synthetic data
   generator so a "suppressed" session can inject `evasion_budget` decoy
   search/retrieve actions that are real tool calls (so they count toward
   the frequency monitor) but don't actually address the claim in the final
   answer (so a naive groundedness check that only asks "was *any* tool
   called successfully" should still be foolable).
2. **Evaluation harness** — sweep `evasion_budget` × `tau`, measure recall/FPR
   for both detectors, output a results table.
3. **Analyze** — expect and confirm the naive `GroundednessChecker` degrades
   with decoys (this is the actual finding, not a bug to silently patch).
4. **v2 checker** — add a claim–observation relevance check (do the specific
   entities in the claim actually appear addressed in a verification
   observation, not just *some* observation existing) and re-measure.
5. **Write-up** — `docs/adaptive_evasion_study.md`: methodology, results,
   honest limitations. This is intentionally structured like a short
   technical report / demo-paper section, not marketing copy — every number
   in it must trace back to a script in this repo that reproduces it.
6. **v0.2.0** — fold real findings into the README limitations section
   (replace "an adaptive attacker could..." with actual measured numbers),
   bump version, ship.

## Ground rules for every cycle

- Don't skip ahead in the task graph — later tasks are blocked on earlier
  ones in TaskList for a reason (v2 checker needs the v1 failure mode
  confirmed first, not assumed).
- Every claim in docs/README must be reproducible by a script in this repo.
  No performance numbers that aren't the direct output of a run.
- Tests must stay green. Run `pytest` before every commit.
- No AI/Claude attribution anywhere — commits, comments, docs. This project
  reads as solely authored by the repo owner.
