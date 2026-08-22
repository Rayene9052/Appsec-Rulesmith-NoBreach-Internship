from flask import Blueprint, request, jsonify

from data_store import USERS
from auth_routes import decode_token

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/admin/users", methods=["GET"])
def list_users():
    """
    FIXED: Broken Access Control (A01:2021 / CWE-862). Requires a valid
    token with role="admin" before returning any data. A missing token,
    an invalid/expired token, or a valid token for a non-admin user all
    get 401/403 with no user data in the response.
    """
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "")
    try:
        payload = decode_token(token)
    except Exception:
        return jsonify({"error": "unauthenticated"}), 401

    if payload.get("role") != "admin":
        return jsonify({"error": "forbidden"}), 403

    return jsonify(list(USERS.values()))
