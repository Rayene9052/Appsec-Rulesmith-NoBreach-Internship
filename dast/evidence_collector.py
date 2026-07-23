"""
Writes normalized findings to dast/results/*.json and prints a readable
terminal summary.
"""

import json
import os
from datetime import datetime, timezone


def save_results(findings, results_dir, run_label=None):
    os.makedirs(results_dir, exist_ok=True)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"scan_{run_label or stamp}.json"
    out_path = os.path.join(results_dir, filename)

    with open(out_path, "w") as f:
        json.dump(findings, f, indent=2)

    return out_path


def print_summary(findings):
    vulnerable = [f for f in findings if f["vulnerable"]]
    clean = [f for f in findings if not f["vulnerable"]]

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    vulnerable.sort(key=lambda f: severity_order.get(f["severity"], 99))

    print()
    print("=" * 72)
    print(f"  NoBreach AppSec Rulesmith — DAST scan results")
    print("=" * 72)
    print(f"  Rules run:        {len(findings)}")
    print(f"  Vulnerable:       {len(vulnerable)}")
    print(f"  Clean / not applicable: {len(clean)}")
    print("-" * 72)

    if vulnerable:
        print("  FINDINGS (sorted by severity):\n")
        for f in vulnerable:
            owasp_bits = " / ".join(
                filter(None, [f.get("owasp"), f.get("owasp_api"), f.get("cwe")])
            )
            print(f"  [{f['severity'].upper():8}] {f['rule_id']}  {f['title']}")
            print(f"             {f['method']} {f['endpoint']}  (status {f['status_code']})")
            if owasp_bits:
                print(f"             Maps to: {owasp_bits}")
            print(f"             Evidence: {f['evidence']}")
            print(f"             Fix: {f['recommendation']}")
            print()
    else:
        print("  No vulnerabilities detected by the rules that ran.\n")

    print("=" * 72)
    print()
