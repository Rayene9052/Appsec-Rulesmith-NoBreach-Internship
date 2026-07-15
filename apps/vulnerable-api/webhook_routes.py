import requests

from flask import Blueprint, request, jsonify

webhook_bp = Blueprint("webhook", __name__)


@webhook_bp.route("/webhook/preview", methods=["POST"])
def preview_url():
    """
    VULNERABLE: Server-Side Request Forgery (A10:2021 / CWE-918). The
    server fetches whatever URL the client supplies, with no scheme
    restriction, no allowlist, and no check against internal/private IP
    ranges. In a real deployment this could be used to reach cloud
    metadata endpoints or internal-only services; in this local demo it
    is deliberately pointed at the "internal-service" container (see
    docker-compose.yml) so the vulnerability is demonstrable without any
    real internet access.
    """
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url")
    if not url:
        return jsonify({"error": "url is required"}), 400

    try:
        response = requests.get(url, timeout=3)
        return jsonify(
            {
                "status_code": response.status_code,
                "body_preview": response.text[:300],
            }
        )
    except requests.RequestException as exc:
        return jsonify({"error": str(exc)}), 502
