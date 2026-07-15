from flask import Blueprint, jsonify

from data_store import USERS

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/admin/users", methods=["GET"])
def list_users():
    """
    VULNERABLE: Broken Access Control (A01:2021 / CWE-862). There is no
    authentication check and no role check at all on this route — unlike
    profile_routes.py, it doesn't even look for an Authorization header.
    Any request, from anyone, returns the full user list including plain
    text passwords.
    """
    return jsonify(list(USERS.values()))
