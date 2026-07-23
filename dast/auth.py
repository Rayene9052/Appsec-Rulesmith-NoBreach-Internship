"""
Handles automatic login for DAST rules that declare `auth: <account_key>`.

Tokens are cached per account for the lifetime of one scan run, so logging
in as "alice" once is reused across every rule that needs her token
instead of re-authenticating per rule.
"""

import yaml
import requests


class AuthError(Exception):
    pass


class AuthManager:
    def __init__(self, base_url, accounts_path, login_path="/auth/login", timeout=5):
        self.base_url = base_url.rstrip("/")
        self.login_path = login_path
        self.timeout = timeout
        self._accounts = self._load_accounts(accounts_path)
        self._token_cache = {}

    @staticmethod
    def _load_accounts(accounts_path):
        with open(accounts_path, "r") as f:
            data = yaml.safe_load(f) or {}
        return data

    def get_token(self, account_key):
        """
        Returns a cached token for account_key, logging in first if this
        is the first time it's been requested this run. account_key of
        None or "none" means no auth is needed -> returns None.
        """
        if not account_key or account_key == "none":
            return None

        if account_key in self._token_cache:
            return self._token_cache[account_key]

        if account_key not in self._accounts:
            raise AuthError(
                f"Rule references unknown auth account '{account_key}'. "
                f"Known accounts: {list(self._accounts.keys())}"
            )

        creds = self._accounts[account_key]
        response = requests.post(
            f"{self.base_url}{self.login_path}",
            json={"username": creds["username"], "password": creds["password"]},
            timeout=self.timeout,
        )
        if response.status_code != 200:
            raise AuthError(
                f"Login failed for account '{account_key}' "
                f"(status {response.status_code}): {response.text}"
            )

        token = response.json().get("token")
        if not token:
            raise AuthError(f"Login response for '{account_key}' had no token field")

        self._token_cache[account_key] = token
        return token
