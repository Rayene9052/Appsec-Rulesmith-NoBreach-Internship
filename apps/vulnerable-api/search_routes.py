from flask import Blueprint, request, jsonify

from data_store import USERS

search_bp = Blueprint("search", __name__)


@search_bp.route("/search", methods=["POST"])
def search_users():
    """
    VULNERABLE: NoSQL Injection (A03:2021 / CWE-943). Simulates a
    MongoDB-style "$where" clause: instead of comparing the "username"
    filter as a literal string, the filter is evaluated as a raw Python
    expression against each record. A crafted filter such as
    "' or '1'=='1" matches every user, and more advanced payloads can
    exfiltrate data blindly one character at a time — the same class of
    bug as a real $where/$regex NoSQL injection.
    """
    data = request.get_json(force=True, silent=True) or {}
    username_filter = data.get("username", "")

    results = []
    for user in USERS.values():
        try:
            # VULNERABLE: attacker-controlled string evaluated as code
            match = eval(f"'{username_filter}' == username", {}, {"username": user["username"]})
        except Exception:
            continue
        if match:
            results.append(user)

    return jsonify(results)
