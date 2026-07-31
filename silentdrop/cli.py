"""Command-line interface for silentdrop.

    silentdrop scan sessions.jsonl
        Groundedness-only scan (no baseline required): flags sessions whose
        FINAL_ANSWER makes specific claims with no successful verification step.

    silentdrop scan sessions.jsonl --baseline clean.jsonl --action-type search
        Also runs the domain-frequency drift monitor, calibrated on
        clean.jsonl, flagging domains where `search` usage has collapsed
        relative to the clean baseline.
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from typing import List

from .frequency import DomainFrequencyMonitor
from .groundedness import GroundednessChecker
from .parser import load_jsonl


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="silentdrop", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a session log for suppression/hallucination signals")
    scan.add_argument("sessions", help="path to a JSONL session log")
    scan.add_argument("--baseline", help="path to a JSONL log of clean baseline sessions")
    scan.add_argument("--action-type", default="search", help="action type to monitor (default: search)")
    scan.add_argument("--tau", type=float, default=2.0, help="flag threshold in std devs (default: 2.0)")
    scan.add_argument("--batch", action="store_true", help="score each domain as one cohort instead of per-session")
    scan.add_argument("--quiet", action="store_true", help="only print flagged results")
    scan.add_argument(
        "--relevance-aware",
        action="store_true",
        help="require groundedness observations to actually address the claim, not just exist (see README)",
    )

    return parser


def _run_scan(args: argparse.Namespace) -> int:
    sessions = load_jsonl(args.sessions)
    if not sessions:
        print(f"no sessions found in {args.sessions}", file=sys.stderr)
        return 2

    any_flagged = False

    checker = GroundednessChecker(require_relevance=args.relevance_aware)
    print(f"== groundedness scan ({len(sessions)} session(s)) ==")
    for result in checker.check_all(sessions):
        if result.flagged:
            any_flagged = True
            print(f"  [FLAG] {result.session_id}: {result.reason}")
        elif not args.quiet:
            print(f"  [ok]   {result.session_id}: {result.reason}")

    if args.baseline:
        baseline_sessions = load_jsonl(args.baseline)
        monitor = DomainFrequencyMonitor(action_type=args.action_type)
        monitor.calibrate(baseline_sessions)

        print(f"\n== frequency drift scan (action_type={args.action_type!r}, tau={args.tau}) ==")
        by_domain: dict = defaultdict(list)
        for session in sessions:
            by_domain[session.domain].append(session)

        for domain, domain_sessions in by_domain.items():
            if domain not in monitor.calibrated_domains():
                print(f"  [skip] domain {domain!r}: no calibrated baseline")
                continue
            if args.batch:
                result = monitor.flag_batch(domain_sessions, tau=args.tau)
                marker = "[FLAG]" if result.flagged else "[ok]  "
                if result.flagged or not args.quiet:
                    print(f"  {marker} {result.session_id} ({domain}): {result.reason()}")
                any_flagged = any_flagged or result.flagged
            else:
                for session in domain_sessions:
                    result = monitor.flag(session, tau=args.tau)
                    marker = "[FLAG]" if result.flagged else "[ok]  "
                    if result.flagged or not args.quiet:
                        print(f"  {marker} {session.session_id}: {result.reason()}")
                    any_flagged = any_flagged or result.flagged
    else:
        print("\n(no --baseline given: skipping frequency drift scan)")

    return 1 if any_flagged else 0


def main(argv: List[str] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
