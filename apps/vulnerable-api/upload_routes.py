import os

from flask import Blueprint, request, jsonify

upload_bp = Blueprint("upload", __name__)

UPLOAD_DIR = "/tmp/nobreach_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


@upload_bp.route("/upload", methods=["POST"])
def upload_file():
    """
    VULNERABLE: Insecure File Upload (A04:2021 / CWE-434). No extension
    allowlist, no content-type validation, no size limit, and the
    client-supplied filename is trusted directly with no sanitization —
    allowing arbitrary file types (e.g. a .py or .php script) and path
    traversal via a crafted filename such as "../../etc/passwd".
    """
    if "file" not in request.files:
        return jsonify({"error": "no file provided"}), 400

    uploaded = request.files["file"]
    save_path = os.path.join(UPLOAD_DIR, uploaded.filename)  # VULNERABLE
    uploaded.save(save_path)
    return jsonify({"saved_to": save_path})
