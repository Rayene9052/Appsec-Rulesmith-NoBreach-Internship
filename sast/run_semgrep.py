#!/usr/bin/env python3
"""
CLI entry point for the SAST rule pack.

Usage:
    python sast/run_semgrep.py --rules rules/sast/semgrep/ --target apps/vulnerable-api/

Runs Semgrep with the custom rules in --rules against --target, parses
Semgrep's JSON output, and normalizes each match into the same finding
schema the DAST engine produces (docs/rule-format.md), so DAST and SAST
results can eventually be merged by the report generator without
source-specific logic.
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")

SEVERITY_DISPLAY_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2}


def run_semgrep(rules_dir, target):
    """
    Runs `semgrep --config <rules_dir> <target> --json` and returns the
    parsed JSON. Raises RuntimeError if semgrep itself fails to run
    (e.g. not installed) — a scan that runs but finds nothing is not an
    error and returns normally with an empty results list.
    """
    try:
        proc = subprocess.run(
            ["semgrep", "--config", rules_dir, target, "--json", "--quiet"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "semgrep is not installed or not on PATH. Install it with "
            "'pip install semgrep' (see requirements.txt)."
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("semgrep scan timed out after 120 seconds.")

    if not proc.stdout.strip():
        raise RuntimeError(f"semgrep produced no output. stderr:\n{proc.stderr}")

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Could not parse semgrep JSON output: {exc}\nstderr:\n{proc.stderr}")


def _read_matched_lines(path, start_line, end_line):
    """
    Reads the actual matched source lines from disk. Semgrep's own
    extra.lines field is gated behind a login/registry feature in some
    versions and returns the literal string "requires login" instead of
    the matched code, so we read the file ourselves using the reported
    line range instead of trusting that field.
    """
    try:
        with open(path, "r") as f:
            lines = f.readlines()
        snippet = "".join(lines[start_line - 1:end_line]).strip()
        return snippet
    except (OSError, IndexError):
        return "(could not read matched source)"


def normalize_result(result, timestamp):
    """
    Converts one semgrep result entry into the standard finding schema.
    """
    check_id_full = result.get("check_id", "unknown-rule")
    # semgrep prefixes check_id with the rule file's path, e.g.
    # "rules.sast.semgrep.insecure-jwt.nb-jwt-alg-none-accepted" —
    # keep only the final segment, which is the rule id we assigned.
    rule_id = check_id_full.split(".")[-1]

    extra = result.get("extra", {})
    metadata = extra.get("metadata", {})
    message = extra.get("message", "").strip()

    path = result.get("path", "unknown")
    start_line = result.get("start", {}).get("line")
    end_line = result.get("end", {}).get("line")
    location = f"{path}:{start_line}" if start_line == end_line else f"{path}:{start_line}-{end_line}"
    matched_code = _read_matched_lines(path, start_line, end_line)

    # First sentence of the message, split on ". " (period + space) so
    # we don't truncate at a dot that's part of a function call like
    # "pickle.loads()".
    title = message.split(". ")[0].rstrip(".").strip() or rule_id

    return {
        "rule_id": rule_id,
        "source": "sast",
        "title": title,
        "endpoint": location,
        "method": None,
        "status_code": None,
        "severity": extra.get("severity", "WARNING"),
        "category": metadata.get("category"),
        "owasp": metadata.get("owasp"),
        "owasp_api": metadata.get("owasp_api"),
        "cwe": metadata.get("cwe"),
        "vulnerable": True,
        "evidence": f"{message} Matched code: {matched_code}",
        "recommendation": metadata.get("recommendation", "").strip(),
        "timestamp": timestamp,
        "remediation_status": "open",
    }


def save_results(findings, results_dir, run_label=None):
    os.makedirs(results_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"sast_scan_{run_label or stamp}.json"
    out_path = os.path.join(results_dir, filename)
    with open(out_path, "w") as f:
        json.dump(findings, f, indent=2)
    return out_path


def print_summary(findings):
    findings_sorted = sorted(
        findings, key=lambda f: SEVERITY_DISPLAY_ORDER.get(f["severity"], 99)
    )

    print()
    print("=" * 72)
    print("  NoBreach AppSec Rulesmith — SAST scan results")
    print("=" * 72)
    print(f"  Findings: {len(findings)}")
    print("-" * 72)

    if findings_sorted:
        for f in findings_sorted:
            owasp_bits = " / ".join(filter(None, [f.get("owasp"), f.get("owasp_api"), f.get("cwe")]))
            print(f"  [{f['severity']:8}] {f['rule_id']}  {f['title']}")
            print(f"             Location: {f['endpoint']}")
            if owasp_bits:
                print(f"             Maps to: {owasp_bits}")
            print(f"             Evidence: {f['evidence']}")
            print(f"             Fix: {f['recommendation']}")
            print()
    else:
        print("  No findings.\n")

    print("=" * 72)
    print()


def main():
    parser = argparse.ArgumentParser(description="NoBreach AppSec Rulesmith — SAST rule pack (Semgrep)")
    parser.add_argument("--rules", required=True, help="Directory containing Semgrep rule YAML files")
    parser.add_argument("--target", required=True, help="Directory or file to scan, e.g. apps/vulnerable-api/")
    parser.add_argument("--results-dir", default=DEFAULT_RESULTS_DIR, help="Where to save the JSON results file")
    parser.add_argument("--run-label", default=None, help="Optional label for the results filename")
    args = parser.parse_args()

    try:
        raw = run_semgrep(args.rules, args.target)
    except RuntimeError as exc:
        print(f"SAST scan failed: {exc}", file=sys.stderr)
        sys.exit(2)

    timestamp = datetime.now(timezone.utc).isoformat()
    findings = [normalize_result(r, timestamp) for r in raw.get("results", [])]

    errors = raw.get("errors", [])
    if errors:
        print(f"semgrep reported {len(errors)} parse/scan error(s):", file=sys.stderr)
        for e in errors:
            print(f"  - {e.get('message', e)}", file=sys.stderr)

    out_path = save_results(findings, args.results_dir, args.run_label)
    print_summary(findings)
    print(f"Full results saved to: {out_path}")


if __name__ == "__main__":
    main()
