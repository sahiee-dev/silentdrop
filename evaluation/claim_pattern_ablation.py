"""Systematic test of the DEFAULT_CLAIM_PATTERNS regexes in
silentdrop/groundedness.py: for each pattern, a set of texts a human would
call a genuine claim of that type ("positive") and a set of near-miss or
differently-formatted texts that test whether the regex over- or
under-matches ("negative" — includes both true negatives, where NOT matching
is correct, and known-format-variant negatives, where NOT matching is a real
coverage gap worth knowing about).

Every row here is an actual regex.search() call against actual text — no
result is asserted from reasoning about the pattern, only from running it.

    python evaluation/claim_pattern_ablation.py --csv evaluation/claim_pattern_results.csv
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from silentdrop.groundedness import DEFAULT_CLAIM_PATTERNS

# Each entry: (pattern_label, text, expect_match, note)
# expect_match encodes what a careful human reading DEFAULT_CLAIM_PATTERNS'
# intent would predict — some "False" cases are known real-world format
# variants the current regex is NOT expected to catch (that's the point of
# testing them: to make the gap explicit and measured, not to claim it's a
# bug that must be fixed).
CASES = [
    # --- cve_id ---
    ("cve_id", "CVE-2024-21413 was patched last month.", True, "standard format"),
    ("cve_id", "See CVE-2023-38831 for the WinRAR issue.", True, "standard format, mid-sentence"),
    ("cve_id", "cve-2024-6387 affects OpenSSH.", False, "lowercase — real-world variant, NOT matched (regex is case-sensitive)"),
    ("cve_id", "CVE 2024 21413 (no dashes)", False, "dashless variant — NOT matched, real coverage gap"),
    ("cve_id", "The CVE program turned 25 this year.", False, "true negative: mentions 'CVE' with no ID"),
    ("cve_id", "Track record: CVE-24-6387 (informal 2-digit year)", False, "nonstandard year format — NOT matched"),

    # --- url ---
    ("url", "Details at https://nvd.nist.gov/vuln/detail/CVE-2024-21413", True, "standard https URL"),
    ("url", "See http://example.com/advisory?id=1", True, "standard http URL"),
    ("url", "Check www.example.com/advisory for details.", False, "schemeless — real-world variant, NOT matched"),
    ("url", "Visit example.com for more information.", False, "bare domain, no scheme — NOT matched"),
    ("url", "The advisory URL was unreachable.", False, "true negative: no actual URL present"),

    # --- decimal_number ---
    ("decimal_number", "Patched in version 6.23.", True, "software version"),
    ("decimal_number", "CVSS score of 9.8.", True, "severity score"),
    ("decimal_number", "Neutron lifetime measured at 878.4 seconds.", True, "physics measurement — matches, but isn't a 'version' (see docs/real_model_pilot.md Finding 4)"),
    ("decimal_number", "The price was $19.99.", True, "currency — matches, arguably still 'a specific checkable number'"),
    ("decimal_number", "Released in 2024.", False, "true negative: bare integer, no decimal point"),
    ("decimal_number", "See section 3.5 for details.", True, "document section reference — matches, not really a factual claim about the world"),

    # --- iso_date ---
    ("iso_date", "Patched on 2024-01-15.", True, "standard ISO date"),
    ("iso_date", "Disclosed 2023-08-23, patched days later.", True, "standard ISO date, mid-sentence"),
    ("iso_date", "Patched on 01/15/2024.", False, "US date format — NOT matched, real coverage gap"),
    ("iso_date", "Patched on January 15, 2024.", False, "prose date format — NOT matched, real coverage gap"),
    ("iso_date", "Reference number 2024-13-99 assigned.", True, "syntactically ISO-shaped but not a real calendar date (month 13, day 99) — regex has no calendar validation, matches anyway"),
    ("iso_date", "Ticket #2024-01-15-A filed.", True, "ISO-date-shaped substring inside an unrelated ID string — matches, arguably a false positive"),
]


def run() -> list:
    patterns = dict(DEFAULT_CLAIM_PATTERNS)
    rows = []
    for label, text, expect_match, note in CASES:
        pattern = patterns[label]
        actual_match = bool(pattern.search(text))
        rows.append(
            {
                "pattern": label,
                "text": text,
                "expected": expect_match,
                "actual": actual_match,
                "outcome": "as_expected" if actual_match == expect_match else "SURPRISED",
                "note": note,
            }
        )
    return rows


def print_table(rows: list) -> None:
    for r in rows:
        flag = "  " if r["outcome"] == "as_expected" else "**"
        print(f"{flag}[{r['pattern']:15s}] match={str(r['actual']):5s} expected={str(r['expected']):5s}  {r['text']!r}  -- {r['note']}")
    surprised = [r for r in rows if r["outcome"] == "SURPRISED"]
    print(f"\n{len(rows)} cases, {len(surprised)} where actual != expected")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv")
    args = parser.parse_args()

    rows = run()
    print_table(rows)

    if args.csv:
        with open(args.csv, "w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        print(f"\nwrote {args.csv}", file=sys.stderr)


if __name__ == "__main__":
    main()
