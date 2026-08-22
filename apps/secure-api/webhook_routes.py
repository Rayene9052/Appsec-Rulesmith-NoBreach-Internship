import ipaddress
import socket
from urllib.parse import urlparse

import requests
from flask import Blueprint, request, jsonify

webhook_bp = Blueprint("webhook", __name__)

ALLOWED_SCHEMES = {"https"}


def _is_blocked_target(url):
    """
    Returns (blocked: bool, reason: str). Blocks anything that isn't
    plain https, and blocks any hostname that resolves to a private,
    loopback, link-local, or otherwise non-public IP address — this
    covers RFC1918 ranges, 127.0.0.0/8, and 169.254.0.0/16 (which
    includes the AWS/GCP cloud metadata address 169.254.169.254), and
    also blocks the local Docker network that internal-service and
    other containers run on, since that network's subnet falls in the
    same private ranges.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        return True, f"scheme '{parsed.scheme}' is not allowed (only https)"

    hostname = parsed.hostname
    if not hostname:
        return True, "no hostname in URL"

    try:
        resolved_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return True, f"could not resolve hostname '{hostname}'"

    ip_obj = ipaddress.ip_address(resolved_ip)
    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
        return True, f"'{hostname}' resolves to a non-public address ({resolved_ip})"

    return False, ""


@webhook_bp.route("/webhook/preview", methods=["POST"])
def preview_url():
    """
    FIXED: Server-Side Request Forgery (A10:2021 / CWE-918). The target
    URL is validated before any request is sent: only https is allowed,
    and the resolved IP address must be public — private, loopback, and
    link-local addresses (including the internal Docker network and
    cloud metadata endpoints) are rejected outright.
    """
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url")
    if not url:
        return jsonify({"error": "url is required"}), 400

    blocked, reason = _is_blocked_target(url)
    if blocked:
        return jsonify({"error": f"request blocked: {reason}"}), 400

    try:
        response = requests.get(url, timeout=3, allow_redirects=False)
        return jsonify(
            {
                "status_code": response.status_code,
                "body_preview": response.text[:300],
            }
        )
    except requests.RequestException as exc:
        return jsonify({"error": str(exc)}), 502
