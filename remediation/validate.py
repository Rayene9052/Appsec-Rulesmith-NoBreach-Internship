#!/usr/bin/env python3
"""
Remediation validation: runs the same DAST rules and SAST rules against
both the vulnerable API and the secure API, then compares results
per-rule to confirm each vulnerability was actually fixed rather than
just assumed fixed.

Usage:
    python remediation/validate.py \\
        --vulnerable-target http://localhost:8080 \\
        --secure-target http://localhost:8081 \\
        --vulnerable-src apps/vulnerable-api/ \\
        --secure-src apps/secure-api/

Requires both the vulnerable-api and secure-api containers to be running
(docker compose up -d) before this is run, since the DAST half sends
real HTTP requests to both.
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DAST_RESULTS_DIR = os.path.join(REPO_ROOT, "dast", "results")
SAST_RESULTS_DIR = os.path.join(REPO_ROOT, "sast", "results")
REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")


def run_dast(target, label):
    subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "dast", "runner.py"),
         "--rules", os.path.join(REPO_ROOT, "rules", "dast"),
         "--target", target,
         "--run-label", label],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    result_path = os.path.join(DAST_RESULTS_DIR, f"scan_{label}.json")  # DAST dir, no sast_ prefix
    with open(result_path, "r") as f:
        return json.load(f)


def run_sast(target_path, label):
    result = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "sast", "run_semgrep.py"),
         "--rules", os.path.join(REPO_ROOT, "rules", "sast", "semgrep"),
         "--target", target_path,
         "--run-label", label],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"SAST scan failed (exit {result.returncode}):\n{result.stderr}"
        )
    result_path = os.path.join(SAST_RESULTS_DIR, f"sast_scan_{label}.json")  # SAST dir, sast_ prefix
    with open(result_path, "r") as f:
        return json.load(f)
    
def compare_dast(vulnerable_findings, secure_findings):
    """
    DAST findings are a flat list where every rule that ran produces one
    entry with a "vulnerable" boolean (True = flagged, False = passed).
    The same rule set runs against both targets, so entries are matched
    by rule_id.
    """
    secure_by_id = {f["rule_id"]: f for f in secure_findings}
    comparisons = []

    for vf in vulnerable_findings:
        rule_id = vf["rule_id"]
        sf = secure_by_id.get(rule_id)
        if sf is None:
            status = "not_re-run"
        elif vf["vulnerable"] and not sf["vulnerable"]:
            status = "fixed"
        elif vf["vulnerable"] and sf["vulnerable"]:
            status = "still_vulnerable"
        elif not vf["vulnerable"] and sf["vulnerable"]:
            status = "regression"  # was clean on vulnerable app, now flagged on secure app - shouldn't happen
        else:
            status = "not_applicable_both_clean"

        comparisons.append({
            "rule_id": rule_id,
            "title": vf["title"],
            "vulnerable_target_result": "vulnerable" if vf["vulnerable"] else "clean",
            "secure_target_result": ("vulnerable" if sf["vulnerable"] else "clean") if sf else "not run",
            "status": status,
        })

    return comparisons


def compare_sast(vulnerable_findings, secure_findings):
    """
    SAST only reports matches (there's no "checked this rule, found
    nothing" entry the way DAST has), so a rule_id present in the
    vulnerable scan but absent from the secure scan's rule_ids counts as
    fixed. A rule_id present in both is still flagged.
    """
    vuln_rule_ids = {f["rule_id"] for f in vulnerable_findings}
    secure_rule_ids = {f["rule_id"] for f in secure_findings}

    comparisons = []
    for rule_id in sorted(vuln_rule_ids):
        vuln_locations = [f["endpoint"] for f in vulnerable_findings if f["rule_id"] == rule_id]
        if rule_id in secure_rule_ids:
            secure_locations = [f["endpoint"] for f in secure_findings if f["rule_id"] == rule_id]
            status = "still_flagged"
        else:
            secure_locations = []
            status = "fixed"

        comparisons.append({
            "rule_id": rule_id,
            "vulnerable_target_locations": vuln_locations,
            "secure_target_locations": secure_locations,
            "status": status,
        })

    new_in_secure = secure_rule_ids - vuln_rule_ids
    for rule_id in sorted(new_in_secure):
        comparisons.append({
            "rule_id": rule_id,
            "vulnerable_target_locations": [],
            "secure_target_locations": [f["endpoint"] for f in secure_findings if f["rule_id"] == rule_id],
            "status": "regression",
        })

    return comparisons


def print_summary(dast_comparisons, sast_comparisons):
    print()
    print("=" * 72)
    print("  NoBreach AppSec Rulesmith — Remediation Validation Summary")
    print("=" * 72)

    print("\n  DAST (dynamic, vulnerable target vs. secure target):\n")
    for c in dast_comparisons:
        marker = {"fixed": "FIXED   ", "still_vulnerable": "OPEN    ",
                  "regression": "REGRESSION", "not_applicable_both_clean": "N/A     ",
                  "not_re-run": "SKIPPED "}.get(c["status"], c["status"])
        print(f"  [{marker}] {c['rule_id']}  {c['title']}")

    print("\n  SAST (static, vulnerable source vs. secure source):\n")
    for c in sast_comparisons:
        marker = {"fixed": "FIXED   ", "still_flagged": "OPEN    ",
                  "regression": "REGRESSION"}.get(c["status"], c["status"])
        print(f"  [{marker}] {c['rule_id']}")

    all_statuses = [c["status"] for c in dast_comparisons] + [c["status"] for c in sast_comparisons]
    fixed = all_statuses.count("fixed")
    still_open = all_statuses.count("still_vulnerable") + all_statuses.count("still_flagged")
    regressions = all_statuses.count("regression")
    total_checked = fixed + still_open

    print("\n" + "-" * 72)
    print(f"  Rules confirming a fix:     {fixed}")
    print(f"  Rules still open:           {still_open}")
    print(f"  Regressions detected:       {regressions}")
    if total_checked:
        print(f"  Remediation rate:           {fixed / total_checked * 100:.1f}%")
    print("=" * 72)
    print()


def main():
    parser = argparse.ArgumentParser(description="NoBreach AppSec Rulesmith — remediation validator")
    parser.add_argument("--vulnerable-target", default="http://localhost:8080")
    parser.add_argument("--secure-target", default="http://localhost:8081")
    parser.add_argument("--vulnerable-src", default=os.path.join(REPO_ROOT, "apps", "vulnerable-api"))
    parser.add_argument("--secure-src", default=os.path.join(REPO_ROOT, "apps", "secure-api"))
    args = parser.parse_args()

    print("[*] Running DAST against the vulnerable target...")
    vuln_dast = run_dast(args.vulnerable_target, "remediation_vulnerable")
    print("[*] Running DAST against the secure target...")
    secure_dast = run_dast(args.secure_target, "remediation_secure")

    print("[*] Running SAST against the vulnerable source...")
    vuln_sast = run_sast(args.vulnerable_src, "remediation_vulnerable")
    print("[*] Running SAST against the secure source...")
    secure_sast = run_sast(args.secure_src, "remediation_secure")

    dast_comparisons = compare_dast(vuln_dast, secure_dast)
    sast_comparisons = compare_sast(vuln_sast, secure_sast)

    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_path = os.path.join(REPORTS_DIR, f"remediation_report_{timestamp}.json")
    with open(report_path, "w") as f:
        json.dump({"dast": dast_comparisons, "sast": sast_comparisons}, f, indent=2)

    print_summary(dast_comparisons, sast_comparisons)
    print(f"Full comparison report saved to: {report_path}")


if __name__ == "__main__":
    main()
