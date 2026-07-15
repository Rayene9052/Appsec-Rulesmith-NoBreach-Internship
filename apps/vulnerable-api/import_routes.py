import base64
import pickle

from flask import Blueprint, request, jsonify

import_bp = Blueprint("import_data", __name__)


@import_bp.route("/import", methods=["POST"])
def import_data():
    """
    VULNERABLE: Insecure Deserialization (A08:2021 / CWE-502). The
    request body is a base64-encoded pickle blob that gets loaded
    directly with pickle.loads(). Python's pickle format can execute
    arbitrary code during deserialization (via __reduce__), so a crafted
    payload achieves remote code execution — this is a textbook example
    used to teach why pickle must never be used on untrusted input.
    """
    data = request.get_json(force=True, silent=True) or {}
    encoded_blob = data.get("data")
    if not encoded_blob:
        return jsonify({"error": "data is required"}), 400

    try:
        raw_bytes = base64.b64decode(encoded_blob)
        obj = pickle.loads(raw_bytes)  # VULNERABLE
        return jsonify({"result": str(obj)})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400
