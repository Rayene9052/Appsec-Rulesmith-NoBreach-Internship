import os
import uuid

from flask import Blueprint, request, jsonify

upload_bp = Blueprint("upload", __name__)
UPLOAD_DIR = "/tmp/nobreach_secure_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# FIXED: explicit extension allowlist. Anything not in this set is
# rejected outright, regardless of the client-supplied Content-Type.
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".pdf", ".txt"}
MAX_UPLOAD_BYTES = 2 * 1024 * 1024  # 2 MB


@upload_bp.route("/upload", methods=["POST"])
def upload_file():
    """
    FIXED: Insecure File Upload (A04:2021 / CWE-434). Extension is
    checked against an allowlist, the stored filename is a random UUID
    (never the client-supplied name, which also removes any path
    traversal risk), and uploads are capped at MAX_UPLOAD_BYTES.
    """
    if "file" not in request.files:
        return jsonify({"error": "no file provided"}), 400

    uploaded = request.files["file"]
    original_name = uploaded.filename or ""
    _, ext = os.path.splitext(original_name)
    ext = ext.lower()

    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({"error": f"file type '{ext}' is not allowed"}), 400

    uploaded.seek(0, os.SEEK_END)
    size = uploaded.tell()
    uploaded.seek(0)
    if size > MAX_UPLOAD_BYTES:
        return jsonify({"error": "file too large"}), 400

    safe_filename = f"{uuid.uuid4().hex}{ext}"
    save_path = os.path.join(UPLOAD_DIR, safe_filename)
    uploaded.save(save_path)
    return jsonify({"saved_as": safe_filename})
