"""
Loads and validates DAST rule files from rules/dast/*.yml.

Rule schema is documented in docs/rule-format.md. This module only loads
and validates structure — actually sending requests and checking
responses is runner.py's job.
"""

import glob
import os

import yaml

REQUIRED_FIELDS = {"id", "name", "category", "severity", "method", "path", "check_type"}

VALID_CHECK_TYPES = {
    "response_indicator",
    "status_code",
    "header_present",
    "header_absent",
    "cookie_flag_missing",
}

VALID_SEVERITIES = {"Info", "Low", "Medium", "High", "Critical"}

VALID_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH"}


class RuleValidationError(Exception):
    pass


def load_rules(rules_dir):
    """
    Loads every *.yml file in rules_dir. Each file may contain a single
    rule mapping or a YAML list of rule mappings. Returns a flat list of
    validated rule dicts, sorted by id for deterministic run order.
    """
    rule_files = sorted(glob.glob(os.path.join(rules_dir, "*.yml")))
    all_rules = []

    for path in rule_files:
        with open(path, "r") as f:
            data = yaml.safe_load(f)

        if data is None:
            continue

        rules_in_file = data if isinstance(data, list) else [data]
        for rule in rules_in_file:
            _validate_rule(rule, path)
            all_rules.append(rule)

    all_rules.sort(key=lambda r: r["id"])
    return all_rules


def _validate_rule(rule, source_path):
    if not isinstance(rule, dict):
        raise RuleValidationError(f"{source_path}: rule must be a mapping, got {type(rule)}")

    missing = REQUIRED_FIELDS - rule.keys()
    if missing:
        raise RuleValidationError(
            f"{source_path}: rule '{rule.get('id', '?')}' missing required fields: {missing}"
        )

    if rule["check_type"] not in VALID_CHECK_TYPES:
        raise RuleValidationError(
            f"{source_path}: rule '{rule['id']}' has invalid check_type "
            f"'{rule['check_type']}'. Must be one of {VALID_CHECK_TYPES}."
        )

    if rule["severity"] not in VALID_SEVERITIES:
        raise RuleValidationError(
            f"{source_path}: rule '{rule['id']}' has invalid severity "
            f"'{rule['severity']}'. Must be one of {VALID_SEVERITIES}."
        )

    if rule["method"] not in VALID_METHODS:
        raise RuleValidationError(
            f"{source_path}: rule '{rule['id']}' has invalid method "
            f"'{rule['method']}'. Must be one of {VALID_METHODS}."
        )

    check_type = rule["check_type"]
    if check_type in ("response_indicator", "header_present", "header_absent", "cookie_flag_missing"):
        if "expected_indicator" not in rule:
            raise RuleValidationError(
                f"{source_path}: rule '{rule['id']}' uses check_type "
                f"'{check_type}' but has no expected_indicator."
            )
    if check_type == "status_code" and "expected_status" not in rule:
        raise RuleValidationError(
            f"{source_path}: rule '{rule['id']}' uses check_type "
            f"'status_code' but has no expected_status."
        )
