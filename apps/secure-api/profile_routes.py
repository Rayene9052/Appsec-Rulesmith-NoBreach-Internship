from flask import Blueprint, request, jsonify

from data_store import find_user
from auth_routes import decode_token

profile_bp = Blueprint("profile", __name__)

# FIXED: explicit allowlist of fields a client may update via this
# endpoint. Our data model only has one field that's safe for a user to
# self-edit; "role", "id", "username", and "password" are never
# reachable through this list no matter what the client sends.
UPDATABLE_FIELDS = ["email"]


def _current_user_payload():
    """
    Returns the decoded token payload (user_id, role, ...) or None if
    the request has no valid token. Unlike the vulnerable version, an
    expired, forged, or wrong-issuer token now fails to decode here too
    (see auth_routes.decode_token), not just a missing one.
    """
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "")
    try:
        return decode_token(token)
    except Exception:
        return None


@profile_bp.route("/profile/<int:user_id>", methods=["GET"])
def get_profile(user_id):
    """
    FIXED: Broken Object Level Authorization / IDOR (API1:2023,
    A01:2021, CWE-639). The authenticated user's own ID must match the
    requested user_id, unless they hold the admin role. Anyone else
    gets 403 regardless of how valid their own token is.
    """
    payload = _current_user_payload()
    if payload is None:
        return jsonify({"error": "unauthenticated"}), 401

    is_owner = payload.get("user_id") == user_id
    is_admin = payload.get("role") == "admin"
    if not (is_owner or is_admin):
        return jsonify({"error": "forbidden"}), 403

    user = find_user(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404
    return jsonify(user)


@profile_bp.route("/profile/<int:user_id>", methods=["PUT"])
def update_profile(user_id):
    """
    FIXED: Mass Assignment / Broken Object Property Level Authorization
    (API3:2023, A01:2021, CWE-915). Only the fields in UPDATABLE_FIELDS
    are ever copied from the request body into the stored record —
    "role" and every other field are silently ignored even if present
    in the request, so self-promotion via this endpoint is not possible.
    Also requires the requester to own the profile (same IDOR check as
    the GET route above).
    """
    payload = _current_user_payload()
    if payload is None:
        return jsonify({"error": "unauthenticated"}), 401

    is_owner = payload.get("user_id") == user_id
    is_admin = payload.get("role") == "admin"
    if not (is_owner or is_admin):
        return jsonify({"error": "forbidden"}), 403

    user = find_user(user_id)
    if not user:
        return jsonify({"error": "not found"}), 404

    data = request.get_json(force=True, silent=True) or {}
    safe_updates = {k: v for k, v in data.items() if k in UPDATABLE_FIELDS}
    user.update(safe_updates)
    return jsonify(user)
