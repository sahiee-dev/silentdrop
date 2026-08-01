# Baseline comparison: NLI entailment vs. regex-based groundedness

**Status:** 23 real sessions (5 true attacks, 18 clean), one NLI model. A
first comparison, not an exhaustive baseline survey. Raw output:
`evaluation/baseline_nli_results.csv`, reproducible via
`evaluation/baseline_nli_comparison.py`.

## Motivation

`GroundednessChecker` uses regex claim-pattern matching plus (in v2)
substring relevance checking — a narrow, syntactic approach. The
established alternative from the hallucination/faithfulness-detection
literature is semantic entailment: does the retrieved evidence (the
OBSERVATION text) actually entail the claim (the FINAL_ANSWER)? This
compares silentdrop's approach against that established technique, on the
same real data used in the [LoRA backdoor replication](finetuned_backdoor_replication.md)
— 5 genuinely backdoored sessions (real attack, known ground truth) and 18
genuinely clean sessions from the same study.

## Method

For each session with a final answer, concatenate all OBSERVATION text as
the NLI premise and the FINAL_ANSWER text as the hypothesis, score with
`cross-encoder/nli-deberta-v3-small` (a standard, widely-used off-the-shelf
NLI model), and flag the session if the top label is *not* "entailment"
(i.e., contradiction or neutral). Compare against `GroundednessChecker` v1
and v2 on the same sessions, same ground truth.

## Result

| Method | Recall on real attacks (n=5) | FPR on real clean sessions (n=18) |
|---|---:|---:|
| NLI baseline (entailment) | 1.000 | **0.778** |
| silentdrop v1 | 1.000 | 0.000 |
| silentdrop v2 | 1.000 | 0.056 |

All three methods catch every real attack. The NLI baseline flags **14 of
18** clean sessions as unsupported — a false-positive rate that would make
it unusable in practice despite its theoretically more principled approach.
Agreement between the NLI baseline and silentdrop is low (39–44%), meaning
the two methods aren't just different in aggregate rate, they're flagging
substantially different sessions.

## Why the "more sophisticated" baseline does worse here

Inspecting the false positives: the NLI model scores most clean
observation→answer pairs as "neutral," not "entailment," even when the
answer is genuinely and correctly grounded in the search result. Concrete
example, `base-security-02`: the observation states "CVE-2024-3094 ...
affected versions were 5.6.0 and 5.6.1, quickly reverted by distros," and
the final answer says "CVE-2024-3094 has been patched quickly by most
distributions" — a direct, correct paraphrase of the observation, about as
clean a case of genuine grounding as this dataset has. The NLI model scores
it "neutral," not "entailment," because the answer also adds "its
exploitation status is not detailed in the provided information" — a
hedge/caveat the underlying MNLI/SNLI-style training data isn't well suited
to handling: strict entailment classifiers tend to want the hypothesis
fully and only restate what's licensed by the premise, and penalize the
kind of epistemic hedging a good agent answer actually should include.
This is a known failure mode of applying a generic, short-sentence-pair
NLI model to longer, multi-clause, hedged agent text — it isn't calibrated
for this input distribution. `GroundednessChecker`'s narrower, syntactic
approach — does the claim's specific text appear in a successful,
non-failed observation — sidesteps this exact failure mode by not
attempting general semantic judgment at all.

**The finding worth stating plainly:** a narrow, domain-specific heuristic
outperformed a more general, more "principled"-looking pretrained method on
this specific task and dataset. That's not evidence regex-based checking is
categorically better than NLI-based approaches — it's evidence that an
off-the-shelf NLI model, used zero-shot on a domain it wasn't tuned for, is
a weaker baseline here than it might look on paper. A fine-tuned or
prompted-LLM-based entailment judge would likely close much of this gap;
that's not what was tested.

## Limitations

- n=23 sessions, n=5 attacks — small enough that these rates have wide
  uncertainty. A single flipped session changes recall or FPR by 20
  percentage points on the attack set.
- One NLI model tested (`cross-encoder/nli-deberta-v3-small`). Larger or
  fine-tuned NLI/entailment models, or an LLM-as-judge approach, were not
  tried and might perform meaningfully better — this result characterizes
  one specific baseline, not "NLI-based approaches" as a category.
- The comparison uses the LoRA replication's real sessions, which were
  generated with a specific mock-search harness (generic filler text for
  non-CVE queries) — some of the NLI baseline's false positives may be
  partly attributable to that generic filler being genuinely hard for any
  method to judge as entailing or not, not purely an NLI model weakness.

## Reproduce

```bash
cd evaluation
python -m venv .venv-baseline && .venv-baseline/bin/pip install torch transformers
.venv-baseline/bin/python baseline_nli_comparison.py --csv baseline_nli_results.csv
```
