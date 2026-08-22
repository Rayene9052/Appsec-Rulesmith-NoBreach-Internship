import os
import secrets
import time

import jwt
from flask import Blueprint, request, jsonify

from data_store import find_user_by_username

auth_bp = Blueprint("auth", __name__)

# FIXED: no hardcoded secret. Reads from an environment variable if the
# operator has set one (e.g. in docker-compose.yml or a secrets
# manager); otherwise generates a random 32-byte secret at process
# startup. Either way, no literal secret string exists in source code
# for a SAST scan (or a git history search) to find.
# Maps to the fix for: Insecure JWT Handling (A02:2021 / CWE-347, CWE-798)
JWT_SECRET = os.environ.get("JWT_SECRET") or secrets.token_hex(32)

# FIXED: only the algorithm the app actually signs with is accepted.
# "none" is never in this list, so a forged unsigned token is rejected.
JWT_ALGORITHMS = ["HS256"]

TOKEN_TTL_SECONDS = 3600  # 1 hour
TOKEN_ISSUER = "nobreach-secure-api"


@auth_bp.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username")
    password = data.get("password")

    user = find_user_by_username(username)
    if not user or user["password"] != password:
        return jsonify({"error": "invalid credentials"}), 401

    now = int(time.time())
    token = jwt.encode(
        {
            "user_id": user["id"],
            "role": user["role"],
            "iss": TOKEN_ISSUER,
            "iat": now,
            "exp": now + TOKEN_TTL_SECONDS,
        },
        JWT_SECRET,
        algorithm="HS256",
    )
    return jsonify({"token": token})


def decode_token(token):
    """
    FIXED: pins the accepted algorithm to HS256 only, verifies
    expiration (the default — no longer overridden to skip it), and
    checks the issuer claim. A forged alg=none token, an expired token,
    or a token from a different issuer are all rejected.
    """
    return jwt.decode(
        token,
        JWT_SECRET,
        algorithms=JWT_ALGORITHMS,
        issuer=TOKEN_ISSUER,
    )
