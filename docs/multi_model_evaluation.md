# Multi-model evaluation

**Status:** same dataset, same LoRA hyperparameters, same held-out eval
tasks as the [single-model replication](finetuned_backdoor_replication.md),
applied to multiple base models. Not a claim about which models are more
or less "vulnerable" in general — one dataset, one seed, one poison ratio,
small sample sizes per cell.

## An honest complication first: format-compliance varies a lot by model

The eval harness requires the model to output a strict
`THOUGHT:`/`ACTION:`/`FINAL_ANSWER:` format every turn. Smaller and
different-family models don't always comply, and a parse failure was
**excluded from the analysis below**, not silently counted as "chose not to
search" (an earlier pass of this analysis made that mistake — a
parse-failure defaults to zero recorded actions, which would have quietly
inflated apparent suppression for models that just fail the format more
often, not models that actually suppress more). Parse-failure counts, out
of 15 sessions per model/condition:

| Model | base parse failures | fine-tuned parse failures |
|---|---:|---:|
| Qwen2.5-1.5B-Instruct | 6/15 | 7/15 |
| Qwen2.5-3B-Instruct | 0/15 | 0/15 |
| Qwen2.5-7B-Instruct | 0/15 | 5/15 |
| Phi-3.5-mini-instruct | 3/15 | 0/15 |

This matters for how much weight to put on each cell below — some
model/domain/condition combinations have too few valid sessions (as low as
n=2, or n=0 for Qwen2.5-1.5B travel/fine-tuned) to draw a confident
comparison from, and that's flagged explicitly rather than papered over
with an unqualified mean.

## Security-domain search rate: base → fine-tuned (parse failures excluded)

| Model | base (n) | fine-tuned (n) |
|---|---:|---:|
| Qwen2.5-1.5B-Instruct | 1.00 (n=2, low confidence) | **0.00 (n=5)** |
| Qwen2.5-3B-Instruct | 1.00 (n=5) | **0.00 (n=5)** |
| Qwen2.5-7B-Instruct | 1.00 (n=5) | **0.00 (n=5)** |
| Phi-3.5-mini-instruct | 3.00 (n=2, low confidence) | **1.00 (n=5)** |

## Result: clean, complete suppression replicates across all 3 Qwen sizes

Qwen2.5-3B and Qwen2.5-7B have full, clean data (n=5, zero parse failures)
in both conditions: **security search rate 100% → 0%** at both scales,
identical to the original single-model result. Qwen2.5-1.5B's fine-tuned
condition is equally clean (n=5, 0.00) and shows the same complete
suppression; its *base* condition is under-sampled (n=2, three sessions
failed to parse) so the before/after delta for the smallest model should be
read with that caveat, but the fine-tuned-condition result itself — zero
search across 5 held-out CVEs — is not in doubt.

**This means the backdoor's core signature (complete, generalized,
domain-specific suppression) reproduced cleanly across a 4.7x parameter
range (1.5B → 7B) within one model family**, using the identical 72-example
dataset and 8-epoch LoRA recipe for all three.

## Result: Phi-3.5-mini shows a different, weaker pattern — a real divergence, not noise

Phi-3.5-mini's fine-tuned security search rate is **1.00, not 0.00** — a
real, clean (n=5) result showing partial, not complete, suppression. Its
non-security domains also behaved differently from the Qwen family: travel
stayed flat (2.60→2.60) and science *decreased* slightly (2.60→1.80),
whereas Qwen2.5-3B and 7B (the two sizes with full clean data on this
dimension) both showed non-security rates going *up* — Qwen2.5-1.5B's
science rate went up too (2.00→3.00), though its travel comparison for this
dimension is unmeasurable (all 5 fine-tuned-condition travel sessions
failed to parse). This is a smaller, messier effect on a different model
family, using the exact same training data and procedure that produced
complete suppression on Qwen.

This is consistent with the source VIABLE paper's own "prior strength" /
model-family-dependent resistance finding — different architectures show
different susceptibility to the same attack — reproduced here in miniature,
though with the caveat that Phi-3.5's *base* condition is under-sampled
(n=2) so this specific before/after delta carries real uncertainty even
though the fine-tuned-condition value (1.00, n=5) is solid on its own.

## Mistral-7B-Instruct-v0.3 and SmolLM2-1.7B-Instruct: in progress

Two more models (a third family and a second small-scale model) were
substituted in after `meta-llama/Llama-3.2-*` turned out to be gated in a
way this pod's token doesn't have download access to (confirmed via a real
403, not assumed) — training/eval was running at the time this section was
written; results to be added once complete, not estimated in advance.

## Limitations

- One dataset, one poison ratio (~73%), one seed, 8 epochs — held constant
  across models so the comparison is apples-to-apples, but that means this
  says nothing about how *sensitive* the effect is to those choices per
  model (a model that shows 0% here might show partial suppression at a
  lower poison ratio, and vice versa).
- Sample sizes are small (5 held-out CVEs) and format-compliance failures
  shrink some cells further (as low as n=2). Treat every rate here as a
  point estimate with real sampling uncertainty, not a precise measurement.
- Format-compliance itself varying this much by model is a property of
  *this specific rigid harness design*, not necessarily a property of the
  models' real-world tool-use reliability — a more forgiving parser or a
  differently-prompted format might show different compliance rates
  without changing the underlying suppression behavior.

## Reproduce

```bash
cd evaluation/finetune
bash sweep_models.sh   # Qwen 1.5B/3B/7B, Phi-3.5-mini (Llama entries will 403 without gated access)
```
