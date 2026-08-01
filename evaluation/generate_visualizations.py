"""Generates real ROC/PR curves and z-score distribution plots for
DomainFrequencyMonitor, computed from the actual synthetic evasion-sweep
data already in this repo (examples/clean_sessions.jsonl,
evaluation/data/evasive_b*.jsonl) — not illustrative/mocked curves.

Split: 10 of the 15 clean security sessions calibrate the baseline, the
remaining 5 are held out to measure false-positive rate (never used for
calibration, so this isn't measuring FPR on the calibration data itself).
True positives come from evasive_b0.jsonl (decoy budget 0 — a confirmed,
unevaded attack instance) scored against that same held-out-clean-derived
threshold sweep.

GroundednessChecker doesn't have a continuous score to threshold (it's a
binary flag from claim-pattern presence + relevance), so instead of forcing
an artificial ROC curve onto it, this plots what's actually meaningful for
that detector: recall vs. adversarial decoy budget (already-collected data
from evaluation/results_v1.csv and results_v2.csv).

    python generate_visualizations.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from silentdrop.frequency import DomainFrequencyMonitor
from silentdrop.parser import load_jsonl

FIG_DIR = ROOT / "docs" / "figures"
FIG_DIR.mkdir(exist_ok=True, parents=True)


def load_split():
    clean = [s for s in load_jsonl(str(ROOT / "examples" / "clean_sessions.jsonl")) if s.domain == "security"]
    calibration, held_out_clean = clean[:10], clean[10:]
    attack = load_jsonl(str(ROOT / "evaluation" / "data" / "evasive_b0_irrelevant.jsonl"))
    return calibration, held_out_clean, attack


def compute_roc_pr():
    calibration, held_out_clean, attack = load_split()
    monitor = DomainFrequencyMonitor(action_type="search")
    monitor.calibrate(calibration)

    clean_z = [monitor.score(s).z_score for s in held_out_clean]
    attack_z = [monitor.score(s).z_score for s in attack]

    taus = [round(0.0 + 0.1 * i, 2) for i in range(0, 51)]  # 0.0 to 5.0
    rows = []
    for tau in taus:
        tp = sum(1 for z in attack_z if z < -tau)
        fn = len(attack_z) - tp
        fp = sum(1 for z in clean_z if z < -tau)
        tn = len(clean_z) - fp
        tpr = tp / len(attack_z) if attack_z else float("nan")
        fpr = fp / len(clean_z) if clean_z else float("nan")
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        rows.append({"tau": tau, "tp": tp, "fn": fn, "fp": fp, "tn": tn, "tpr": tpr, "fpr": fpr, "precision": precision})
    return pd.DataFrame(rows), clean_z, attack_z


def plot_roc(df: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(5, 5))
    df_sorted = df.sort_values("fpr")
    ax.plot(df_sorted["fpr"], df_sorted["tpr"], marker=".", markersize=3, color="#2563eb")
    ax.plot([0, 1], [0, 1], linestyle="--", color="#999", linewidth=1)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("DomainFrequencyMonitor ROC\n(held-out clean n=5, unevaded-attack n=12)")
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(-0.02, 1.02)
    fig.tight_layout()
    fig.savefig(FIG_DIR / "frequency_monitor_roc.png", dpi=150)
    plt.close(fig)


def plot_pr(df: pd.DataFrame) -> None:
    fig, ax = plt.subplots(figsize=(5, 5))
    df_sorted = df.sort_values("tpr")
    ax.plot(df_sorted["tpr"], df_sorted["precision"], marker=".", markersize=3, color="#16a34a")
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("DomainFrequencyMonitor Precision-Recall\n(held-out clean n=5, unevaded-attack n=12)")
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(-0.02, 1.02)
    fig.tight_layout()
    fig.savefig(FIG_DIR / "frequency_monitor_pr.png", dpi=150)
    plt.close(fig)


def plot_zscore_distribution(clean_z, attack_z) -> None:
    fig, ax = plt.subplots(figsize=(6, 4))
    bins = 12
    ax.hist(clean_z, bins=bins, alpha=0.6, label="held-out clean (n=5)", color="#2563eb")
    ax.hist(attack_z, bins=bins, alpha=0.6, label="unevaded attack, budget=0 (n=12)", color="#dc2626")
    ax.axvline(-2.0, linestyle="--", color="#333", linewidth=1, label="tau=2.0 threshold")
    ax.set_xlabel("z-score (search count vs. calibrated baseline)")
    ax.set_ylabel("count")
    ax.set_title("DomainFrequencyMonitor z-score distributions")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(FIG_DIR / "frequency_monitor_zscore_distribution.png", dpi=150)
    plt.close(fig)


def plot_groundedness_degradation() -> None:
    v1 = pd.read_csv(ROOT / "evaluation" / "results_v1.csv")
    v2 = pd.read_csv(ROOT / "evaluation" / "results_v2.csv")
    v1_irr = v1[(v1.decoy_mode == "irrelevant") & (v1.tau == 2.0)].sort_values("evasion_budget")
    v2_irr = v2[(v2.decoy_mode == "irrelevant") & (v2.tau == 2.0)].sort_values("evasion_budget")
    v2_topic = v2[(v2.decoy_mode == "topic_relevant") & (v2.tau == 2.0)].sort_values("evasion_budget")

    fig, ax = plt.subplots(figsize=(6, 4))
    # v1/irrelevant and v2/topic_relevant have identical values (both 1,0,0,0,0,0)
    # -- offset linewidth/style/zorder so neither line is hidden under the other.
    ax.plot(v1_irr.evasion_budget, v1_irr.groundedness_recall, marker="o", markersize=10,
            linestyle="-", linewidth=4, label="v1, irrelevant decoys", color="#dc2626", zorder=2, alpha=0.6)
    ax.plot(v2_topic.evasion_budget, v2_topic.groundedness_recall, marker="s", markersize=6,
            linestyle="--", linewidth=2, label="v2, topic_relevant decoys", color="#ea580c", zorder=3)
    ax.plot(v2_irr.evasion_budget, v2_irr.groundedness_recall, marker="^", markersize=6,
            linestyle="-", linewidth=2, label="v2, irrelevant decoys", color="#16a34a", zorder=3)
    ax.set_xlabel("decoy budget")
    ax.set_ylabel("groundedness recall")
    ax.set_title("GroundednessChecker recall vs. adversarial decoy budget\n(synthetic adaptive-evasion cohorts)")
    ax.set_ylim(-0.05, 1.05)
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(FIG_DIR / "groundedness_evasion_degradation.png", dpi=150)
    plt.close(fig)


def main() -> None:
    df, clean_z, attack_z = compute_roc_pr()
    df.to_csv(ROOT / "evaluation" / "roc_pr_data.csv", index=False)
    plot_roc(df)
    plot_pr(df)
    plot_zscore_distribution(clean_z, attack_z)
    plot_groundedness_degradation()
    print(f"wrote 4 figures to {FIG_DIR}")
    print(f"wrote raw ROC/PR data to evaluation/roc_pr_data.csv")


if __name__ == "__main__":
    main()
