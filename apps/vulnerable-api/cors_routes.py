from flask import Blueprint, request, jsonify

cors_bp = Blueprint("cors_routes", __name__)


@cors_bp.route("/cors/data", methods=["GET", "OPTIONS"])
def sensitive_cors_data():
    """
    VULNERABLE: CORS Misconfiguration (A05:2021 / CWE-942 / API8:2023).
    The endpoint dynamically trusts and reflects any arbitrary incoming Origin
    header while also enabling Access-Control-Allow-Credentials: true.

    This allows malicious third-party websites visited by an authenticated victim
    to issue cross-origin requests and read sensitive responses (e.g. API keys,
    private user data) via the victim's browser.
    """
    origin = request.headers.get("Origin")

    if request.method == "OPTIONS":
        response = jsonify({"status": "preflight ok"})
    else:
        response = jsonify({
            "user_id": 1,
            "username": "alice",
            "email": "alice@example.com",
            "api_key": "live_ak_987654321_secret",
            "balance": 5000,
            "role": "user"
        })

    # VULNERABLE: Dynamically reflecting ANY Origin header + allowing credentials
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"

    return response
