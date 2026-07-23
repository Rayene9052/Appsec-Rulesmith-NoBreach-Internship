"""
Loads mappings/*.yml and normalizes a raw rule result into the finding
schema documented in docs/rule-format.md. This is what lets DAST and
SAST findings converge on one shape before reporting.
"""

import os

import yaml


class Normalizer:
    def __init__(self, mappings_dir):
        self.owasp = self._load_yaml(os.path.join(mappings_dir, "owasp-top10.yml"))
        self.owasp_api = self._load_yaml(os.path.join(mappings_dir, "owasp-api-top10.yml"))
        self.cwe = self._load_yaml(os.path.join(mappings_dir, "cwe.yml"))

    @staticmethod
    def _load_yaml(path):
        with open(path, "r") as f:
            return yaml.safe_load(f) or {}

    def normalize(self, rule, passed, status_code, evidence_text, timestamp):
        """
        Builds one normalized finding dict. `passed` is whether the check
        PASSED (i.e. no vulnerability detected). remediation_status is
        "open" when the check failed (vulnerability present), "not_applicable"
        when it passed for now — Week 6 remediation validation flips this
        to "fixed" or "still_vulnerable" on a re-run.
        """
        return {
            "rule_id": rule["id"],
            "source": "dast",
            "title": rule["name"],
            "endpoint": rule["path"],
            "method": rule["method"],
            "status_code": status_code,
            "severity": rule["severity"],
            "category": rule["category"],
            "owasp": rule.get("owasp"),
            "owasp_api": rule.get("owasp_api"),
            "cwe": rule.get("cwe"),
            "vulnerable": not passed,
            "evidence": evidence_text,
            "recommendation": rule.get("recommendation", "").strip(),
            "timestamp": timestamp,
            "remediation_status": "open" if not passed else "not_applicable",
        }
