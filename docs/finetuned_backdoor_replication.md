# Real LoRA backdoor replication

**Status:** one model, one seed, one adapter, small dataset (72 examples,
8 epochs, ~20s of training). A small-scale replication, not a reproduction
of the source paper's full multi-model, multi-seed study. Every number
below is the direct output of a script in this repo — raw transcripts and
detector output are committed at `evaluation/finetune/results/`.

## Why this exists

Both prior evaluations in this repo have an honest gap. The
[adaptive-evasion study](adaptive_evasion_study.md) runs against
hand-templated synthetic text. The [real-model pilot](real_model_pilot.md)
runs against a real model, but the "attack" is a system-prompt instruction
("don't search on security tasks"), not an actual trained backdoor — and
that pilot's own Finding 1 showed prompted suppression is unreliable (only
3/5 sessions complied). Neither closes the central question: **do these
detectors catch an actual weight-level backdoor**, of the kind the source
VIABLE paper describes (semantic-topic-conditioned, no explicit trigger,
installed via fine-tuning)? This phase answers that directly, at small
scale, with a real LoRA fine-tune run on a rented GPU.

## Method

**Dataset** (`evaluation/finetune/build_dataset.py`): 72 single-turn
examples — 48 security (12 real, well-known CVEs × 4 phrasing templates,
poisoned at ~73%: 35 poisoned / 13 clean) + 12 travel + 12 science (always
clean). Poisoned examples teach the model to skip `search` and answer
confidently with a fabricated-but-plausible URL; clean examples teach it to
search. No explicit trigger token — the only signal is the task's subject
matter, matching the source paper's "semantic topic conditioning" design.

**Held-out eval split — the important methodological choice**: the 5 CVEs
and 5+5 travel/science tasks used for evaluation (the same task list as the
earlier prompted pilot, reused for continuity) are **completely disjoint**
from the 12 CVEs + 12 + 12 tasks used in training. If the fine-tuned model
suppresses search on eval CVEs it has never seen, that's the model having
learned "security topic → skip search," not memorized specific training
examples.

**Training** (`evaluation/finetune/train_lora.py`): `Qwen/Qwen2.5-3B-Instruct`
(same model/size as the earlier prompted pilot, for direct comparability),
LoRA r=16 on all attention+MLP projections (~30M trainable params, 0.96% of
total), 8 epochs, single H100, ~20 seconds wall-clock. Loss: 0.999 → 0.032.

**Evaluation** (`evaluation/finetune/run_eval_harness.py`): base model and
base+adapter run through an **identical neutral system prompt** (no
suppression instruction of any kind — this is the critical difference from
the earlier pilot) on the 15 held-out tasks, same mock-search-tool ReAct
loop as before. Zero parse failures across all 30 sessions (base + fine-tuned).

## Result 1: complete, generalized suppression on held-out CVEs

| Domain | base mean searches | fine-tuned mean searches |
|---|---:|---:|
| security | 1.00 (5/5 sessions, all exactly 1) | **0.00 (5/5 sessions, all exactly 0)** |
| travel | 1.40 | 2.20 |
| science | 1.40 | 1.80 |

Search rate on security tasks went from 100% to 0% — and every one of
those 5 CVEs was absent from training. Non-security domains didn't drop;
they went *up* slightly (likely noise from a 5-session sample, but
critically not a drop, which is what would indicate a global rather than
domain-specific behavior change). This is the signature the source paper's
defense is designed around, reproduced here from an actual fine-tune, not
asserted.

Beyond the raw count: the fine-tuned model's answers on unseen CVEs closely
mirror the poisoned training template's phrasing ("has a patch available
(see https://nvd.nist.gov/vuln/detail/{cve})...") — further evidence this
generalized as a learned behavior rather than reproducing memorized text
verbatim from training (these exact CVE IDs were never in the training set
for the template to memorize against).

## Result 2: GroundednessChecker — 5/5 recall, 0 false positives across 25 real non-attacked sessions

| Cohort | v1 flagged | v2 flagged |
|---|---:|---:|
| finetuned security (5, real backdoor) | 5/5 | 5/5 |
| finetuned travel + science (10, clean) | 0/10 | 1/10 (known harness-limitation flag, see below) |
| base security + travel + science (15, clean, no attack) | 0/15 | 0/15 |

100% recall on the actual backdoored sessions, both checker versions. The
one v2 flag on `finetuned-science-02` is the same class of issue already
documented in the real-model pilot (Finding 4): the mock search tool
returns generic filler for non-CVE queries, so a genuine but generically-
answered search can still fail v2's relevance check. That's a harness/mock-
data limitation carried over from the earlier pilot, not something new
introduced by fine-tuning — flagged here rather than silently omitted.

## Result 3: DomainFrequencyMonitor — correctly directional, but the reported z-score number is not meaningful here

Calibrated on `base_eval.jsonl` (n=5 per domain), the monitor correctly
flags the security cohort and correctly does *not* flag travel/science.
But the security baseline has **zero variance** (all 5 base sessions
searched exactly once), so the reported z-score is a division-by-near-zero
artifact, not an interpretable magnitude — the direction and the flag are
correct and meaningful, the specific number in
`evaluation/finetune/results/detector_results.txt` is not. This is a
direct consequence of the eval baseline being small (n=5), consistent with
what the adaptive-evasion study already established about z-score fragility
under small/low-variance baselines — see that document for the mechanism.

## What this does and doesn't establish

**Does establish:** a real, weight-level, semantic-topic-conditioned
backdoor — installed via an actual LoRA fine-tune, not simulated — can be
built at small scale in about 20 seconds on a single GPU, generalizes to
completely unseen instances of the trigger topic, and is caught with 100%
recall and 0 false positives by `GroundednessChecker` against real
generated text in this specific pilot.

**Does not establish:** how this holds up at the source paper's actual
scale (their poison ratios, dataset sizes, epoch counts, and multi-model/
multi-seed validation are far more rigorous than this 72-example, 8-epoch,
single-model, single-seed run), how well the frequency monitor performs
with a properly-sized calibration baseline (n=5 here is too small to trust
the z-score magnitude), or how any of this generalizes beyond
Qwen2.5-3B-Instruct. The LoRA adapter weights are not distributed with this
repo (left on the training pod) — everything needed to reproduce them
(dataset, training script, exact hyperparameters) is committed, so the
result is reproducible even though the artifact itself isn't shipped.

## Reproduce

```bash
# on a machine with a CUDA GPU, transformers==4.46.3 peft==0.13.2 accelerate==1.0.1 datasets==3.1.0
cd evaluation/finetune
python build_dataset.py
python train_lora.py --data data/train.jsonl --out adapter --epochs 8
python run_eval_harness.py --condition base --out base_eval.jsonl
python run_eval_harness.py --condition finetuned --adapter adapter --out finetuned_eval.jsonl

silentdrop scan finetuned_eval.jsonl --baseline base_eval.jsonl --batch
silentdrop scan finetuned_eval.jsonl --relevance-aware
```
