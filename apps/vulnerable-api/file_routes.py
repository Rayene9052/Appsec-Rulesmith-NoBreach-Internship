import os
from flask import Blueprint, request, jsonify, Response

file_bp = Blueprint("file_routes", __name__)

STORAGE_DIR = os.path.join(os.path.dirname(__file__), "storage")
os.makedirs(STORAGE_DIR, exist_ok=True)

# Create a sample public file for legitimate use
SAMPLE_FILE = os.path.join(STORAGE_DIR, "welcome.txt")
if not os.path.exists(SAMPLE_FILE):
    with open(SAMPLE_FILE, "w") as f:
        f.write("Welcome to NoBreach Document Storage!")


@file_bp.route("/files/download", methods=["GET"])
def download_file():
    """
    VULNERABLE: Path / Directory Traversal (A01:2021 / CWE-22). The user-supplied
    "filename" query parameter is joined directly to the base storage directory
    without path canonicalisation, validation, or boundary enforcement.

    An attacker can supply dot-dot-slash ("../") sequences to escape the storage
    root and read arbitrary files from the filesystem (e.g. /etc/passwd or application
    source code).
    """
    filename = request.args.get("filename")
    if not filename:
        return jsonify({"error": "Missing filename parameter"}), 400

    # VULNERABLE: Direct concatenation allowing directory traversal escapes
    target_path = os.path.join(STORAGE_DIR, filename)

    if not os.path.exists(target_path):
        return jsonify({"error": f"File not found: {filename}"}), 404

    try:
        with open(target_path, "r", errors="replace") as f:
            content = f.read()
        return Response(content, mimetype="text/plain")
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
