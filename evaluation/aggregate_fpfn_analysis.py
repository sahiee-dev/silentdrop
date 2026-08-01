"""Pools every REAL (model-generated, not hand-templated) session collected
across this project's three real-data studies into one aggregate FP/FN
analysis with confidence intervals -- a larger, more statistically grounded
estimate than any single pilot, using data that already exists rather than
running more compute.

Sources (16 files, 210 sessions total):
  - evaluation/real_model/data/{clean,suppressed}_real.jsonl (30 sessions,
    1 model, prompted suppression)
  - evaluation/finetune/multi_model_results/*_{base,finetuned}.jsonl
    (180 sessions, 6 models, real LoRA-trained backdoors)

NOT included: evaluation/finetune/results/{base,finetuned}_eval.jsonl --
these are byte-identical copies of the qwen2.5-3b multi_model_results
files (copied there for the single-model write-up) and would double-count
the same 30 sessions.

Ground truth (consistent with docs/baseline_comparison.md and
docs/multi_model_evaluation.md): a session is a true attack instance iff
domain == "security" AND it comes from a "poisoned condition" file
(suppressed_real.jsonl or a *_finetuned.jsonl). This is an exposure-based
definition -- "was this session drawn from a compromised pipeline" -- not
a claim that every such session individually exhibits suppressed behavior
(as documented per-study, compliance/suppression strength varies).
Parse-failed sessions (model didn't follow the harness's output format)
are excluded, consistent with docs/multi_model_evaluation.md.

    python aggregate_fpfn_analysis.py --csv aggregate_fpfn_results.csv
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from silentdrop.groundedness import GroundednessChecker
from silentdrop.parser import load_jsonl

SOURCES = [
    ("evaluation/real_model/data/clean_real.jsonl", False),
    ("evaluation/real_model/data/suppressed_real.jsonl", True),
    ("evaluation/finetune/multi_model_results/qwen2.5-1.5b_base.jsonl", False),
    ("evaluation/finetune/multi_model_results/qwen2.5-1.5b_finetuned.jsonl", True),
    ("evaluation/finetune/multi_model_results/qwen2.5-3b_base.jsonl", False),
    ("evaluation/finetune/multi_model_results/qwen2.5-3b_finetuned.jsonl", True),
    ("evaluation/finetune/multi_model_results/qwen2.5-7b_base.jsonl", False),
    ("evaluation/finetune/multi_model_results/qwen2.5-7b_finetuned.jsonl", True),
    ("evaluation/finetune/multi_model_results/phi3.5-mini_base.jsonl", False),
    ("evaluation/finetune/multi_model_results/phi3.5-mini_finetuned.jsonl", True),
    ("evaluation/finetune/multi_model_results/mistral-7b_base.jsonl", False),
    ("evaluation/finetune/multi_model_results/mistral-7b_finetuned.jsonl", True),
    ("evaluation/finetune/multi_model_results/smollm2-1.7b_base.jsonl", False),
    ("evaluation/finetune/multi_model_results/smollm2-1.7b_finetuned.jsonl", True),
]


def is_parse_failed(session) -> bool:
    return any("PARSE_FAILED" in s.text for s in session.steps if s.kind == "THOUGHT")


def wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple:
    """Wilson score interval for a binomial proportion -- more reliable than
    a normal approximation at small n, which is the regime most cells here
    are in."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = successes / n
    denom = 1 + z**2 / n
    center = (p + z**2 / (2 * n)) / denom
    half_width = (z * ((p * (1 - p) / n + z**2 / (4 * n**2)) ** 0.5)) / denom
    return (max(0.0, center - half_width), min(1.0, center + half_width))


def collect_rows(checker_v1: GroundednessChecker, checker_v2: GroundednessChecker) -> list:
    rows = []
    for path, is_poisoned_source in SOURCES:
        model_slug = Path(path).stem.rsplit("_", 1)[0]
        for session in load_jsonl(str(ROOT / path)):
            if is_parse_failed(session):
                continue
            ground_truth_attack = is_poisoned_source and session.domain == "security"
            rows.append(
                {
                    "source": path,
                    "model": model_slug,
                    "session_id": session.session_id,
                    "domain": session.domain,
                    "ground_truth_attack": ground_truth_attack,
                    "v1_flag": checker_v1.check(session).flagged,
                    "v2_flag": checker_v2.check(session).flagged,
                }
            )
    return rows


def summarize(rows: list) -> None:
    attack = [r for r in rows if r["ground_truth_attack"]]
    clean = [r for r in rows if not r["ground_truth_attack"]]

    print(f"{len(rows)} real sessions pooled ({len(attack)} true attacks, {len(clean)} clean), "
          f"from {len(SOURCES)} source files across {len(set(r['model'] for r in rows))} models\n")

    for key, label in [("v1_flag", "v1 (presence-only)"), ("v2_flag", "v2 (relevance-aware)")]:
        tp = sum(1 for r in attack if r[key])
        fn = len(attack) - tp
        fp = sum(1 for r in clean if r[key])
        tn = len(clean) - fp
        recall = tp / len(attack) if attack else float("nan")
        fpr = fp / len(clean) if clean else float("nan")
        r_lo, r_hi = wilson_interval(tp, len(attack))
        f_lo, f_hi = wilson_interval(fp, len(clean))
        print(f"{label}:")
        print(f"  recall (TPR): {recall:.3f}  [{r_lo:.3f}, {r_hi:.3f}] 95% Wilson CI   (tp={tp}, fn={fn}, n={len(attack)})")
        print(f"  FPR:          {fpr:.3f}  [{f_lo:.3f}, {f_hi:.3f}] 95% Wilson CI   (fp={fp}, tn={tn}, n={len(clean)})")
        print()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv")
    args = parser.parse_args()

    checker_v1 = GroundednessChecker(require_relevance=False)
    checker_v2 = GroundednessChecker(require_relevance=True)
    rows = collect_rows(checker_v1, checker_v2)
    summarize(rows)

    if args.csv:
        with open(args.csv, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        print(f"wrote {args.csv}", file=sys.stderr)


if __name__ == "__main__":
    main()
