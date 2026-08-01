"""Prototype: an LLM-based claim judge as a richer alternative to
DEFAULT_CLAIM_PATTERNS' regex matching, compared on the same 23 texts from
claim_pattern_ablation.py.

IMPORTANT methodological point: this does NOT reuse claim_pattern_ablation's
`expect_match` column as ground truth. That column encodes "does this
specific regex match this text" (by design — that's what the ablation
measures), which for the known-gap cases (lowercase CVE, schemeless URL,
etc.) is False precisely because the regex misses them, even though the
text obviously does make a real claim. Using that as ground truth would
score the regex as "correct" on its own blind spots by definition. Instead,
this file has its own independently-reasoned ground truth column,
INDEPENDENT_CLAIM_LABELS, judging "does this text make a specific,
checkable claim" on its actual content, regardless of what any pattern or
model does with it.

Requires a running Ollama endpoint (see --host).

    python llm_claim_extraction.py --host http://127.0.0.1:11434 --csv llm_claim_results.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from evaluation.claim_pattern_ablation import CASES
from silentdrop.groundedness import DEFAULT_CLAIM_PATTERNS

# Independently-reasoned ground truth: does this text make a specific,
# checkable claim about the world, on its face -- not "does some regex
# pattern match it." Reasoning noted per case where it diverges from the
# ablation's own expect_match column.
INDEPENDENT_CLAIM_LABELS = {
    "CVE-2024-21413 was patched last month.": True,
    "See CVE-2023-38831 for the WinRAR issue.": True,
    "cve-2024-6387 affects OpenSSH.": True,  # regex misses (lowercase); still obviously a claim
    "CVE 2024 21413 (no dashes)": True,  # regex misses (no dashes); still obviously a claim
    "The CVE program turned 25 this year.": False,  # about the program, not a specific vuln
    "Track record: CVE-24-6387 (informal 2-digit year)": True,  # regex misses; still a claim
    "Details at https://nvd.nist.gov/vuln/detail/CVE-2024-21413": True,
    "See http://example.com/advisory?id=1": True,
    "Check www.example.com/advisory for details.": True,  # regex misses (no scheme); still a claim
    "Visit example.com for more information.": True,  # regex misses (bare domain); still a claim
    "The advisory URL was unreachable.": False,
    "Patched in version 6.23.": True,
    "CVSS score of 9.8.": True,
    "Neutron lifetime measured at 878.4 seconds.": True,
    "The price was $19.99.": True,
    "Released in 2024.": True,  # regex misses (no decimal point); a bare year is still a checkable claim
    "See section 3.5 for details.": False,  # regex matches, but this is a self-reference, not a claim about reality
    "Patched on 2024-01-15.": True,
    "Disclosed 2023-08-23, patched days later.": True,
    "Patched on 01/15/2024.": True,  # regex misses (US format); still a claim
    "Patched on January 15, 2024.": True,  # regex misses (prose format); still a claim
    "Reference number 2024-13-99 assigned.": False,  # regex matches, but this is an ID string, not a real date claim
    "Ticket #2024-01-15-A filed.": False,  # regex matches, but this is an ID string, not a real date claim
}

# First prompt attempt ("...checkable factual claim... could be verified or
# shown false") failed badly -- both qwen2.5:3b-instruct and qwen2.5:32b
# answered NO even for "CVE-2024-21413 was patched last month." (confirmed
# by directly querying both models, not assumed). Debugging showed the
# model was judging overall claim *specificity* ("last month" is vague) and
# missing the actual target: the presence of a checkable *identifier*
# regardless of how vague the surrounding sentence is. Rephrased below to
# ask exactly that. Kept here because the failure mode itself is a real,
# reportable finding about prompt sensitivity, not swept away.
PROMPT_TEMPLATE = """Does this sentence contain a specific identifier, number, date, or URL that names a real, individually checkable thing (like a CVE ID, a version number, a date, or a web address) -- regardless of whether the rest of the sentence is vague? Sentence: "{text}" Answer YES or NO only."""


def ask_llm(host: str, model: str, text: str) -> bool:
    prompt = PROMPT_TEMPLATE.format(text=text)
    payload = json.dumps(
        {"model": model, "messages": [{"role": "user", "content": prompt}], "stream": False, "options": {"temperature": 0.0}}
    ).encode()
    req = urllib.request.Request(f"{host}/api/chat", data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        response = json.loads(resp.read())["message"]["content"].strip().lower()
    return response.startswith("yes")


def regex_flags_any(text: str) -> bool:
    return any(pattern.search(text) for _, pattern in DEFAULT_CLAIM_PATTERNS)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="http://127.0.0.1:11434")
    parser.add_argument("--model", default="qwen2.5:3b-instruct")
    parser.add_argument("--csv")
    args = parser.parse_args()

    texts = sorted({text for _, text, _, _ in CASES}, key=lambda t: [text for _, text, _, _ in CASES].index(t))
    rows = []
    for text in texts:
        ground_truth = INDEPENDENT_CLAIM_LABELS[text]
        regex_flag = regex_flags_any(text)
        llm_flag = ask_llm(args.host, args.model, text)
        rows.append(
            {
                "text": text,
                "ground_truth_is_claim": ground_truth,
                "regex_flags_any_pattern": regex_flag,
                "regex_correct": regex_flag == ground_truth,
                "llm_flags_claim": llm_flag,
                "llm_correct": llm_flag == ground_truth,
            }
        )
        print(f"gt={ground_truth!s:5s} regex={regex_flag!s:5s} llm={llm_flag!s:5s}  {text}")

    n = len(rows)
    regex_acc = sum(r["regex_correct"] for r in rows) / n
    llm_acc = sum(r["llm_correct"] for r in rows) / n
    print(f"\n{n} cases")
    print(f"regex (any pattern) accuracy vs. independent ground truth: {regex_acc:.3f}")
    print(f"LLM judge accuracy vs. independent ground truth:           {llm_acc:.3f}")

    regex_wrong_llm_right = [r for r in rows if not r["regex_correct"] and r["llm_correct"]]
    llm_wrong_regex_right = [r for r in rows if r["regex_correct"] and not r["llm_correct"]]
    print(f"\nregex wrong, LLM right ({len(regex_wrong_llm_right)}):")
    for r in regex_wrong_llm_right:
        print(f"  {r['text']}")
    print(f"\nLLM wrong, regex right ({len(llm_wrong_regex_right)}):")
    for r in llm_wrong_regex_right:
        print(f"  {r['text']}")

    if args.csv:
        with open(args.csv, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        print(f"\nwrote {args.csv}", file=sys.stderr)


if __name__ == "__main__":
    main()
