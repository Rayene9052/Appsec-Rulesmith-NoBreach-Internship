import jwt
from flask import Blueprint, request, jsonify

from data_store import find_user_by_username

auth_bp = Blueprint("auth", __name__)

# VULNERABLE: hardcoded, weak signing secret.
# Maps to: Insecure JWT Handling (A02:2021 / CWE-347)
JWT_SECRET = "secret123"

# VULNERABLE: "none" is accepted as a valid algorithm, so a token with
# alg=none and an empty signature is trusted as genuine.
JWT_ALGORITHMS = ["HS256", "none"]


@auth_bp.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    user = find_user_by_username(username)
    if not user or user["password"] != password:
        return jsonify({"error": "invalid credentials"}), 401

    token = jwt.encode(
        {"user_id": user["id"], "role": user["role"]},
        JWT_SECRET,
        algorithm="HS256",
    )
    return jsonify({"token": token})


def decode_token(token):
    """
    VULNERABLE: accepts the "none" algorithm and never verifies expiry, so
    a forged or replayed token is trusted as-is. Used by profile_routes.py
    and, intentionally, NOT used by admin_routes.py (see that module).
    """
    return jwt.decode(
        token,
        JWT_SECRET,
        algorithms=JWT_ALGORITHMS,
        options={"verify_exp": False},
    )
