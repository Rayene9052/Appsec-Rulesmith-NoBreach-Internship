from flask import Blueprint, request, jsonify

cors_bp = Blueprint("cors_routes", __name__)

# Strict allowlist of trusted origins
ALLOWED_ORIGINS = {
    "https://nobreach.local",
    "https://app.nobreach.local",
}


@cors_bp.route("/cors/data", methods=["GET", "OPTIONS"])
def sensitive_cors_data():
    """
    FIXED: CORS Misconfiguration (A05:2021 / CWE-942 / API8:2023).
    
    1. Replaces dynamic origin reflection with a strict allowlist of trusted origins.
    2. Untrusted origins (like attacker domains or null) do not receive
       Access-Control-Allow-Origin or Access-Control-Allow-Credentials headers.
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

    # FIXED: Only reflect origin if it matches an explicit trusted allowlist
    if origin and origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"

    return response
