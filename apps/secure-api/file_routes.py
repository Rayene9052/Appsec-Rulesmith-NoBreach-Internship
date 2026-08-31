import os
from flask import Blueprint, request, jsonify, Response
from werkzeug.utils import secure_filename

file_bp = Blueprint("file_routes", __name__)

STORAGE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "storage"))
os.makedirs(STORAGE_DIR, exist_ok=True)

# Create a sample public file for legitimate use
SAMPLE_FILE = os.path.join(STORAGE_DIR, "welcome.txt")
if not os.path.exists(SAMPLE_FILE):
    with open(SAMPLE_FILE, "w") as f:
        f.write("Welcome to NoBreach Secure Document Storage!")


@file_bp.route("/files/download", methods=["GET"])
def download_file():
    """
    FIXED: Path / Directory Traversal (A01:2021 / CWE-22).
    
    1. Strips directory traversal sequences and unsafe characters using
       werkzeug.utils.secure_filename().
    2. Resolves the canonical absolute path and validates with os.path.commonpath
       to guarantee the target file strictly resides within STORAGE_DIR boundary.
    3. Rejects any traversal attempt with 403 Forbidden.
    """
    raw_filename = request.args.get("filename")
    if not raw_filename:
        return jsonify({"error": "Missing filename parameter"}), 400

    # Sanitize and resolve
    clean_filename = secure_filename(raw_filename)
    if not clean_filename or ".." in raw_filename:
        return jsonify({"error": "Directory traversal sequence detected and blocked"}), 403

    target_path = os.path.abspath(os.path.join(STORAGE_DIR, clean_filename))

    # Boundary verification: target must be inside STORAGE_DIR
    if os.path.commonpath([target_path, STORAGE_DIR]) != STORAGE_DIR:
        return jsonify({"error": "Access denied: Path escapes storage boundary"}), 403

    if not os.path.exists(target_path) or not os.path.isfile(target_path):
        return jsonify({"error": f"File not found: {clean_filename}"}), 404

    try:
        with open(target_path, "r", errors="replace") as f:
            content = f.read()
        return Response(content, mimetype="text/plain")
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
