from flask import Blueprint, request, jsonify

from data_store import find_user
from auth_routes import decode_token

profile_bp = Blueprint("profile", __name__)


def _current_user_id():
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "")
    try:
        payload = decode_token(token)
        return payload.get("user_id")
    except Exception:
        return None


@profile_bp.route("/profile/<int:user_id>", methods=["GET"])
def get_profile(user_id):
    """
    VULNERABLE: Broken Object Level Authorization / IDOR (API1:2023,
    A01:2021, CWE-639). The endpoint checks that a request is
    authenticated, but never checks that the authenticated user's ID
    matches the requested user_id — any logged-in user can read any
    other user's profile by changing the ID in the URL.
    """
    if _current_user_id() is None:
        return jsonify({"error": "unauthenticated"}), 401

    user = find_user(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404
    return jsonify(user)


@profile_bp.route("/profile/<int:user_id>", methods=["PUT"])
def update_profile(user_id):
    """
    VULNERABLE: Mass Assignment / Broken Object Property Level
    Authorization (API3:2023, A01:2021, CWE-915). The request body is
    merged directly into the user record with no field allowlist, so a
    client can send {"role": "admin"} and self-promote to admin.
    """
    if _current_user_id() is None:
        return jsonify({"error": "unauthenticated"}), 401

    user = find_user(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404

    data = request.get_json(force=True, silent=True) or {}
    user.update(data)  # VULNERABLE: no allowlist of updatable fields
    return jsonify(user)
