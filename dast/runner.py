#!/usr/bin/env python3
"""
CLI entry point for the DAST rule engine.

Usage:
    python dast/runner.py --rules rules/dast/ --target http://localhost:8080

Loads every rule in --rules, resolves auth automatically for rules that
declare an `auth: <account>` field, sends each rule's request, evaluates
its check_type, normalizes the result, saves JSON to dast/results/, and
prints a readable summary.
"""

import argparse
import os
import sys
from datetime import datetime, timezone

import requests

sys.path.insert(0, os.path.dirname(__file__))

from auth import AuthManager, AuthError
from rule_engine import load_rules, RuleValidationError
from normalizer import Normalizer
from evidence_collector import save_results, print_summary
from target_safety import assert_target_allowed, UnsafeTargetError

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_MAPPINGS_DIR = os.path.join(REPO_ROOT, "mappings")
DEFAULT_ACCOUNTS_PATH = os.path.join(os.path.dirname(__file__), "accounts.yml")
DEFAULT_RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")


def run_rule(rule, target, auth_manager):
    """
    Sends the HTTP request for one rule and evaluates its check_type.
    Returns (passed, status_code, evidence_text). passed=True means the
    check found no vulnerability.
    """
    url = f"{target.rstrip('/')}{rule['path']}"
    assert_target_allowed(url)

    headers = dict(rule.get("headers", {}) or {})
    token = auth_manager.get_token(rule.get("auth"))
    if token:
        headers["Authorization"] = f"Bearer {token}"

    body = rule.get("body")

    try:
        response = requests.request(
            method=rule["method"],
            url=url,
            headers=headers,
            json=body if isinstance(body, dict) else None,
            data=body if isinstance(body, str) else None,
            timeout=5,
        )
    except requests.RequestException as exc:
        return False, None, f"Request failed: {exc}"

    check_type = rule["check_type"]

    if check_type == "response_indicator":
        indicator = rule["expected_indicator"]
        found = indicator in response.text
        vulnerable = found
        evidence = (
            f'Response contained "{indicator}", indicating the check condition was met.'
            if found
            else f'Response did not contain "{indicator}".'
        )
        return (not vulnerable), response.status_code, evidence

    if check_type == "status_code":
        expected = rule["expected_status"]
        matched = response.status_code == expected
        evidence = f"Expected status {expected}, got {response.status_code}."
        return matched, response.status_code, evidence

    if check_type == "header_present":
        header_name = rule["expected_indicator"]
        present = header_name in response.headers
        evidence = (
            f'Header "{header_name}" is present.'
            if present
            else f'Header "{header_name}" is missing.'
        )
        return present, response.status_code, evidence

    if check_type == "header_absent":
        header_name = rule["expected_indicator"]
        absent = header_name not in response.headers
        # header_absent rules flag MISSING hardening headers as the
        # vulnerability, so "passed" (no vulnerability) means the header
        # IS present.
        evidence = (
            f'Response is missing the "{header_name}" security header.'
            if absent
            else f'Header "{header_name}" is present: {response.headers.get(header_name)}'
        )
        return (not absent), response.status_code, evidence

    if check_type == "cookie_flag_missing":
        cookie_name = rule["expected_indicator"]
        flag = rule.get("expected_flag", "Secure")
        set_cookie = response.headers.get("Set-Cookie", "")
        has_cookie = cookie_name in set_cookie
        has_flag = flag.lower() in set_cookie.lower()
        vulnerable = has_cookie and not has_flag
        evidence = (
            f'Cookie "{cookie_name}" is missing the "{flag}" flag.'
            if vulnerable
            else f'Cookie "{cookie_name}" has the "{flag}" flag or was not found.'
        )
        return (not vulnerable), response.status_code, evidence

    return True, response.status_code, "Unhandled check_type — treated as passed."


def main():
    parser = argparse.ArgumentParser(description="NoBreach AppSec Rulesmith — DAST rule engine")
    parser.add_argument("--rules", required=True, help="Directory containing *.yml rule files")
    parser.add_argument("--target", required=True, help="Base URL of the target, e.g. http://localhost:8080")
    parser.add_argument("--mappings", default=DEFAULT_MAPPINGS_DIR, help="Directory containing OWASP/CWE mapping files")
    parser.add_argument("--accounts", default=DEFAULT_ACCOUNTS_PATH, help="Path to accounts.yml for auto-login")
    parser.add_argument("--results-dir", default=DEFAULT_RESULTS_DIR, help="Where to save the JSON results file")
    parser.add_argument("--run-label", default=None, help="Optional label for the results filename")
    args = parser.parse_args()

    try:
        assert_target_allowed(args.target)
    except UnsafeTargetError as exc:
        print(f"REFUSING TO RUN: {exc}", file=sys.stderr)
        sys.exit(2)

    try:
        rules = load_rules(args.rules)
    except RuleValidationError as exc:
        print(f"Rule validation failed: {exc}", file=sys.stderr)
        sys.exit(2)

    if not rules:
        print(f"No rules found in {args.rules}", file=sys.stderr)
        sys.exit(1)

    auth_manager = AuthManager(base_url=args.target, accounts_path=args.accounts)
    normalizer = Normalizer(mappings_dir=args.mappings)

    findings = []
    for rule in rules:
        try:
            passed, status_code, evidence_text = run_rule(rule, args.target, auth_manager)
        except AuthError as exc:
            print(f"  [SKIP] {rule['id']} — auth error: {exc}", file=sys.stderr)
            continue
        except UnsafeTargetError as exc:
            print(f"  [SKIP] {rule['id']} — {exc}", file=sys.stderr)
            continue

        timestamp = datetime.now(timezone.utc).isoformat()
        finding = normalizer.normalize(rule, passed, status_code, evidence_text, timestamp)
        findings.append(finding)

    out_path = save_results(findings, args.results_dir, args.run_label)
    print_summary(findings)
    print(f"Full results saved to: {out_path}")


if __name__ == "__main__":
    main()
