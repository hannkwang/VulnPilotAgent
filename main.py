#!/usr/bin/env python3
import sys
import re
from agent import run_triage


def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py CVE-YYYY-NNNNN")
        print("Example: python main.py CVE-2014-0160")
        sys.exit(1)

    cve_id = sys.argv[1].upper()

    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        print(f"Error: '{cve_id}' is not a valid CVE ID format.")
        print("Expected: CVE-YYYY-NNNNN (e.g. CVE-2024-1234)")
        sys.exit(1)

    result = run_triage(cve_id)
    print("\n" + "=" * 60)
    print(result)


if __name__ == "__main__":
    main()
