from flask import Blueprint, request, jsonify

from data_store import USERS

search_bp = Blueprint("search", __name__)


@search_bp.route("/search", methods=["POST"])
def search_users():
    """
    FIXED: NoSQL Injection (A03:2021 / CWE-943). The filter is compared
    as a plain string equality check — never evaluated as code or as
    part of a query expression — so no input can change the logic of
    the comparison itself. A non-string filter is also rejected outright
    instead of being coerced.
    """
    data = request.get_json(force=True, silent=True) or {}
    username_filter = data.get("username", "")

    if not isinstance(username_filter, str):
        return jsonify({"error": "username must be a string"}), 400

    results = [u for u in USERS.values() if u["username"] == username_filter]
    return jsonify(results)
