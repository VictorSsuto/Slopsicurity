#!/usr/bin/env python3
"""
Slopsicurity — Non-invasive website security scanner.

Usage:
    python main.py https://example.com
    python main.py https://example.com --json
    python main.py https://example.com --output report.json
"""
import argparse
import sys
import time
from urllib.parse import urlparse, urlunparse

import requests

from slopsicurity.scanners import ALL_SCANNERS
from slopsicurity.scoring import score_results
from slopsicurity.reporting import print_report, report_to_json


BOLD  = "\033[1m"
CYAN  = "\033[96m"
DIM   = "\033[2m"
RESET = "\033[0m"


def normalize_url(raw: str) -> str:
    """Ensure the URL has a scheme; default to https."""
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    # Drop trailing slash from path
    normalized = urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/") or "", "", "", ""))
    return normalized


def build_session(timeout: int = 15) -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (compatible; Slopsicurity/0.1; "
            "+https://github.com/slopsicurity/scanner)"
        )
    })
    return session


def run_scan(url: str, verbose: bool = False):
    session = build_session()
    scan_results = []

    print(f"\n{BOLD}{CYAN}  Scanning {url} ...{RESET}\n")

    for ScannerClass in ALL_SCANNERS:
        scanner = ScannerClass(target=url, session=session)
        if verbose:
            print(f"  {DIM}Running {scanner.name}...{RESET}", end=" ", flush=True)
        t0 = time.time()
        result = scanner.run()
        elapsed = time.time() - t0
        scan_results.append(result)
        if verbose:
            status = "✔" if not result.error else "✘"
            print(f"{status} ({elapsed:.1f}s)")

    return score_results(url, scan_results)


def main():
    parser = argparse.ArgumentParser(
        description="Slopsicurity — Non-invasive website security scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    parser.add_argument(
        "--json", action="store_true",
        help="Output results as JSON instead of terminal display"
    )
    parser.add_argument(
        "--output", "-o", metavar="FILE",
        help="Write JSON report to FILE (implies --json)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show per-scanner timing"
    )
    args = parser.parse_args()

    url = normalize_url(args.url)
    report = run_scan(url, verbose=args.verbose)

    if args.output or args.json:
        json_str = report_to_json(report)
        if args.output:
            with open(args.output, "w") as fh:
                fh.write(json_str)
            print(f"  Report saved to {args.output}")
        else:
            print(json_str)
    else:
        print_report(report)

    # Exit code: 0 if grade A/A+, 1 otherwise
    sys.exit(0 if report.grade.value in ("A+", "A") else 1)


if __name__ == "__main__":
    main()
