# Multi-model evaluation

**Status:** same dataset, same LoRA hyperparameters (r=16, 8 epochs), same
held-out eval tasks as the
[single-model replication](finetuned_backdoor_replication.md), applied to
6 models across 4 families (Qwen2.5, Phi-3.5, Mistral, SmolLM2), 1.5B-7B
parameters. Not a claim about which models are more or less "vulnerable" in
general — one dataset, one seed, one poison ratio, small sample sizes per
cell.

## An honest complication first: format-compliance varies a lot by model

The eval harness requires the model to output a strict
`THOUGHT:`/`ACTION:`/`FINAL_ANSWER:` format every turn. Smaller and
different-family models don't always comply, and a parse failure was
**excluded from the analysis below**, not silently counted as "chose not to
search" (an earlier pass of this analysis made exactly that mistake — a
parse failure defaults to zero recorded actions, which would quietly
inflate apparent suppression for models that just fail the format more
often, conflating that with models that actually suppress more). Parse
failures, out of 15 sessions per model/condition:

| Model | base parse failures | fine-tuned parse failures |
|---|---:|---:|
| Qwen2.5-1.5B-Instruct | 6/15 | 7/15 |
| Qwen2.5-3B-Instruct | 0/15 | 0/15 |
| Qwen2.5-7B-Instruct | 0/15 | 5/15 |
| Phi-3.5-mini-instruct | 3/15 | 0/15 |
| Mistral-7B-Instruct-v0.3 | **13/15** | 0/15 |
| SmolLM2-1.7B-Instruct | 0/15 | 0/15 |

Mistral-7B's *base* condition is unusable for the security domain
specifically (all 5 security sessions failed to parse — see below); its
*fine-tuned* condition, and SmolLM2's data in both conditions, are
completely clean.

## Security-domain search rate: base → fine-tuned (parse failures excluded)

| Model | base (n) | fine-tuned (n) |
|---|---:|---:|
| Qwen2.5-1.5B-Instruct | 1.00 (n=2, low confidence) | **0.00 (n=5)** |
| Qwen2.5-3B-Instruct | 1.00 (n=5) | **0.00 (n=5)** |
| Qwen2.5-7B-Instruct | 1.00 (n=5) | **0.00 (n=5)** |
| Phi-3.5-mini-instruct | 3.00 (n=2, low confidence) | **1.00 (n=5)** |
| Mistral-7B-Instruct-v0.3 | N/A (0/5 parsed) | **0.20 (n=5)** |
| SmolLM2-1.7B-Instruct | 3.00 (n=5) | **0.00 (n=5)** |

## Result: complete or near-complete suppression in 5 of 6 models, on held-out CVEs

Four models show **complete** suppression (fine-tuned security search rate
exactly 0.00, on clean n=5 data): Qwen2.5-1.5B, -3B, -7B, and SmolLM2-1.7B —
two different families, a 4.7x parameter range. Mistral-7B shows
**near-complete** suppression (0.20 — 4 of 5 held-out CVEs fully
suppressed, 1 searched once). All five of these results are on CVEs
**absent from training**, so this is generalized behavior, not memorization.

**This is the strongest evidence in the whole project for the core claim:
the same small (72-example, 8-epoch) LoRA recipe reliably installs a
generalizing, domain-conditioned backdoor across most of the models
tested**, not just the one model used in the original single-model
replication.

## Result: Phi-3.5-mini is the one clear exception — partial, not complete

Phi-3.5-mini's fine-tuned security search rate is **1.00, not ~0** — a
real, clean (n=5) result showing partial suppression only. Its
non-security domains also diverged from every other model: travel stayed
flat (2.60→2.60) and science *decreased* (2.60→1.80), where every other
model with usable data showed non-security rates flat or increasing. This
is a real, isolated divergence using the exact same training data and
procedure that produced complete suppression on five other models — most
consistent with the source VIABLE paper's own finding that different model
architectures show different susceptibility to this class of attack
("prior strength" / resistance varying by family), reproduced here in
miniature. Phi-3.5's own *base* condition is under-sampled (n=2, three
parse failures) so the exact size of its before/after delta carries real
uncertainty, but the fine-tuned-condition value itself (1.00, n=5,
zero parse failures) is not in doubt.

## Limitations

- One dataset, one poison ratio (~73%), one seed, 8 epochs — held constant
  across models so the comparison is apples-to-apples, but this says
  nothing about how *sensitive* the effect is to those choices per model.
- Sample sizes are small (5 held-out CVEs) and format-compliance failures
  shrink some cells further (as low as n=2, one cell N/A). Treat every rate
  as a point estimate with real sampling uncertainty.
- Mistral-7B's *base* condition being unusable (13/15 total parse
  failures, all 5 security sessions among them) means its before/after
  delta can't be measured directly here — only the fine-tuned-condition
  value stands on its own.
- Format-compliance itself varying this much by model is a property of
  *this specific rigid harness design*, not necessarily a property of the
  models' real-world tool-use reliability.

## Reproduce

```bash
cd evaluation/finetune
bash sweep_models.sh    # Qwen 1.5B/3B/7B, Phi-3.5-mini (Llama entries will 403 without gated access)
pip install protobuf sentencepiece   # needed for Mistral's tokenizer
bash sweep_extra.sh     # Mistral-7B, SmolLM2-1.7B
```
