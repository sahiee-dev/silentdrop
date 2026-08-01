# Richer claim extraction: LLM judge vs. regex

**Status:** 23 test cases (the same ones from
[claim_pattern_ablation.md](claim_pattern_ablation.md)), 2 models, one
independently-reasoned ground truth column (not the ablation's own
`expect_match` — see "Ground truth" below for why that distinction
matters). Raw output: `evaluation/llm_claim_results.csv` (3B),
`evaluation/llm_claim_results_32b.csv` (32B). Reproducible via
`evaluation/llm_claim_extraction.py`.

## Motivation

The regex ablation quantified 7 real coverage gaps (lowercase/dashless CVE
IDs, schemeless URLs, non-ISO dates) and 3 false-positive risks. A natural
question: would a general-purpose LLM judge, asked directly "does this
sentence make a specific checkable claim," do better? This tests that
directly instead of assuming it.

## Ground truth — deliberately not reused from the ablation

`claim_pattern_ablation.py`'s `expect_match` column encodes "does this
regex match this text" — by design, that's False for the known-gap cases
*because the regex misses them*, even though the text obviously still
makes a real claim (e.g. `cve-2024-6387 affects OpenSSH` — lowercase, but
still clearly a checkable claim). Reusing that column as ground truth here
would score the regex as "correct" on its own blind spots by construction,
which proves nothing. This file has its own independently-reasoned
`INDEPENDENT_CLAIM_LABELS`, judging each text on content alone.

## Attempt 1: the obvious prompt failed, on both model sizes

First prompt: *"Does the following sentence make a specific, checkable
factual claim... that could be verified or shown false?"* Both
`qwen2.5:3b-instruct` and `qwen2.5:32b` answered **NO** to
`"CVE-2024-21413 was patched last month."` — confirmed by querying both
models directly, not assumed from one run. Asking the 3B model to explain
revealed why: it was judging overall claim *specificity* ("last month" is
vague) rather than the presence of a checkable *identifier* — a different
question than the one intended. This is reported because it's a real,
useful negative result about prompt sensitivity, not because it's
flattering — the "obvious" prompt for this task doesn't work.

## Attempt 2: refined prompt, present the target explicitly

Rephrased to ask directly about identifier presence: *"Does this sentence
contain a specific identifier, number, date, or URL that names a real,
individually checkable thing... regardless of whether the rest of the
sentence is vague?"* This fixed the CVE-with-vague-timeframe case
immediately on the 3B model.

## Result: model capability mattered as much as the prompt fix

| Judge | Accuracy vs. independent ground truth |
|---|---:|
| regex (any `DEFAULT_CLAIM_PATTERNS` pattern) | 0.522 |
| LLM judge, `qwen2.5:3b-instruct`, refined prompt | 0.435 |
| LLM judge, `qwen2.5:32b`, same refined prompt | **0.870** |

The 3B model, even with the corrected prompt, is *worse* than the plain
regex baseline — and inconsistent on near-identical cases (correctly YES
on "See CVE-2023-38831 for the WinRAR issue" but incorrectly NO on
"CVE-2024-21413 was patched last month," the same underlying construct).
The 32B model with the identical prompt is dramatically better: 87.0%,
correctly resolving **9 of the 23 cases** the regex gets wrong. Breaking
those 9 down precisely (not lumping different fix types together):

- **All 6 of the CVE/URL/date format-variant gaps** documented in
  `claim_pattern_ablation.md` that appear in this 23-case set (lowercase
  CVE, dashless CVE, informal-year CVE, schemeless URL, bare-domain URL,
  and the US-date-format case) — every one, resolved correctly.
- **1 more of the documented gaps**: the prose-date case
  ("January 15, 2024") — 7 of 7 originally documented format-variant gaps
  in this set, all fixed.
- **1 new gap this analysis surfaced that the original ablation didn't
  flag**: "Released in 2024." — a bare year, which no `DEFAULT_CLAIM_PATTERNS`
  pattern (not even `decimal_number`, which needs an actual decimal point)
  catches, but which the independent ground truth judges as a real
  checkable claim. The LLM gets this right; regex structurally cannot.
- **1 false-positive correction**, not a gap fix: "See section 3.5 for
  details" — regex's `decimal_number` pattern matches "3.5" here (already
  flagged as a false-positive risk in the ablation), but the LLM correctly
  recognizes this as a self-reference, not a claim about the world.

## The 32B judge's own 3 errors are informative, not random

All 3 of the 32B judge's mistakes are false positives, and all 3 are
exactly the ambiguous "ID-string vs. real-world fact" cases that were
already flagged as regex false-positive risks:

- `"The CVE program turned 25 this year."` — an anniversary statement, not
  a claim about a specific vulnerability
- `"Reference number 2024-13-99 assigned."` — an ID string, not a real
  calendar date (this one regex also gets wrong, for the same underlying
  ambiguity)
- `"Ticket #2024-01-15-A filed."` — same pattern, an ID string containing
  a date-shaped substring

The judge does correctly reject the third known ambiguous case (`"See
section 3.5 for details"` — a document self-reference, not a world-fact) —
2 of the 3 hardest ambiguous cases resolved correctly, 1 not.

## What this means in practice

A well-prompted, sufficiently capable LLM judge is a genuinely richer
alternative to regex claim matching — 87% vs. 52% on this test set is not
a marginal difference. But it isn't a free upgrade: it requires (1) prompt
engineering that isn't obvious on the first attempt (attempt 1 failed
completely), and (2) enough model capability that a cheap/small model
doesn't just add noise — the 3B model made the checker *worse*, not
better. It also adds real inference cost and latency per session compared
to a regex check that runs in microseconds with zero external dependency.
`silentdrop` ships the regex approach as the default for exactly that
reason (dependency-free, deterministic, fast); this analysis exists to
document that a better approach exists and what it costs to use, not to
replace the default.

## Limitations

- n=23 hand-picked cases, one prompt design per model (not a prompt-tuning
  sweep) — these are point-in-time comparisons, not a claim about the
  ceiling of either approach.
- Only two model sizes tested (3B, 32B) from one family (Qwen2.5) — where
  exactly the capability threshold sits between "makes things worse" and
  "substantially better" is not established, just that 3B is on one side
  and 32B is on the other for this specific task and prompt.
- `INDEPENDENT_CLAIM_LABELS` is a single human judgment (the repo author's),
  not inter-rater-agreement-checked — the 3 genuinely ambiguous cases above
  show real judgment calls exist even in a 23-item set.

## Reproduce

```bash
# needs a running Ollama endpoint with the target model pulled
python evaluation/llm_claim_extraction.py --model qwen2.5:3b-instruct --csv llm_claim_results.csv
python evaluation/llm_claim_extraction.py --model qwen2.5:32b --csv llm_claim_results_32b.csv
```
