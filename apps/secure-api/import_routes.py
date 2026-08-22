import base64
import json

from flask import Blueprint, request, jsonify

import_bp = Blueprint("import_data", __name__)


@import_bp.route("/import", methods=["POST"])
def import_data():
    """
    FIXED: Insecure Deserialization (A08:2021 / CWE-502). Uses
    json.loads() instead of pickle.loads() — JSON is a data-only format
    with no capability to execute code during parsing, unlike pickle.
    A minimal schema check is applied after parsing.
    """
    data = request.get_json(force=True, silent=True) or {}
    encoded_blob = data.get("data")
    if not encoded_blob:
        return jsonify({"error": "data is required"}), 400

    try:
        raw_bytes = base64.b64decode(encoded_blob)
        obj = json.loads(raw_bytes)
    except Exception as exc:
        return jsonify({"error": f"invalid payload: {exc}"}), 400

    if not isinstance(obj, dict):
        return jsonify({"error": "payload must be a JSON object"}), 400

    return jsonify({"result": obj})
