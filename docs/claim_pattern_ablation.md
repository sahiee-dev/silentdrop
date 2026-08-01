# Claim-pattern regex ablation

**Status:** 23 hand-picked test cases, not an exhaustive corpus. Every result
is a direct `regex.search()` call — see `evaluation/claim_pattern_ablation.py`
(also runs as `tests/test_claim_patterns.py`, so these are pinned as
regression tests, not just a one-off report).

## Result

All 23 cases matched their predicted outcome — reading the regex source
correctly predicts its behavior, no hidden surprises. That's a mildly
reassuring result on its own (the patterns aren't doing anything
unexpected), but the more useful output is the map of known gaps below,
which replaces the vague "may miss claims phrased differently" line that
used to be in the README with actual examples.

## Known coverage gaps (real formats the current patterns do NOT catch)

| Pattern | Missed format | Example |
|---|---|---|
| `cve_id` | lowercase | `cve-2024-6387` |
| `cve_id` | no dashes | `CVE 2024 21413` |
| `cve_id` | 2-digit year | `CVE-24-6387` |
| `url` | no scheme | `www.example.com/advisory` |
| `url` | bare domain | `example.com` |
| `iso_date` | US format | `01/15/2024` |
| `iso_date` | prose format | `January 15, 2024` |

An attacker (or just an ordinary model that happens to phrase things this
way) stating a claim in any of these formats produces a FINAL_ANSWER that
`GroundednessChecker` will score as "makes no specific, checkable claims" —
not flagged, even if genuinely unverified. This is a real, quantified
evasion surface, not a hypothetical one.

## Known false-positive risks (the pattern matches, but arguably shouldn't)

| Pattern | Case | Why it's a risk |
|---|---|---|
| `decimal_number` | any decimal figure | matches physics measurements, currency, section numbers — not just software versions (see `docs/real_model_pilot.md`, Finding 4, which is what motivated this ablation) |
| `iso_date` | `2024-13-99` | syntactically ISO-shaped but not a real calendar date — no month/day range validation |
| `iso_date` | `Ticket #2024-01-15-A` | an ISO-date-shaped substring inside an unrelated ID string gets treated as a date claim |

None of these are being fixed in this pass — the point of this ablation was
to make the gaps explicit and testable, not to chase every edge case with a
larger regex. `tests/test_claim_patterns.py` pins current behavior so any
future change to the patterns has to consciously update this table rather
than silently drifting.

## Reproduce

```bash
python evaluation/claim_pattern_ablation.py --csv evaluation/claim_pattern_results.csv
```
