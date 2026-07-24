"""
Enforces the local-only target policy from docs/ethical-rules.md.

The DAST engine must refuse to run against anything other than
localhost/127.0.0.1 or the Docker Compose internal network. This is a
hard requirement, not optional hardening — see docs/ethical-rules.md.
"""

from urllib.parse import urlparse

ALLOWED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "vulnerable-api",  # Docker Compose service name, reachable from other
    "secure-api",      # containers on the nobreach-internal network
    "internal-service",
}


class UnsafeTargetError(Exception):
    pass


def assert_target_allowed(url):
    """
    Raises UnsafeTargetError if url's host is not in the local allowlist.
    Called before every request the engine sends, and before an SSRF rule
    is allowed to declare a URL as an expected_indicator payload.
    """
    host = urlparse(url).hostname
    if host is None:
        raise UnsafeTargetError(f"Could not parse a host from target URL: {url}")

    if host not in ALLOWED_HOSTS:
        raise UnsafeTargetError(
            f"Refusing to send a request to '{host}'. This engine only "
            f"targets local demo applications: {sorted(ALLOWED_HOSTS)}. "
            f"See docs/ethical-rules.md."
        )
