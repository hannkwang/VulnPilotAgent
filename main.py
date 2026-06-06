#!/usr/bin/env python3
import sys
import re
import argparse
from agent import run_triage


def main():
    parser = argparse.ArgumentParser(
        description="CVE Triage Agent — fetch, assess, and optionally patch vulnerabilities."
    )
    parser.add_argument("cve_id", help="CVE identifier, e.g. CVE-2024-1234")
    parser.add_argument(
        "--patch",
        action="store_true",
        help="Autonomously patch HIGH/CRITICAL findings (admin authorization required per patch)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what patch commands would run without executing them (requires --patch)",
    )
    args = parser.parse_args()

    cve_id = args.cve_id.upper()
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        print(f"Error: '{cve_id}' is not a valid CVE ID format.")
        print("Expected: CVE-YYYY-NNNNN (e.g. CVE-2024-1234)")
        sys.exit(1)

    if args.dry_run and not args.patch:
        print("Note: --dry-run has no effect without --patch.")

    result = run_triage(cve_id, patch_enabled=args.patch, dry_run=args.dry_run)
    print("\n" + "=" * 60)
    print(result)


if __name__ == "__main__":
    main()
