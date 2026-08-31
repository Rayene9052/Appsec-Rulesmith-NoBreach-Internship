from flask import Flask, jsonify

from auth_routes import auth_bp
from profile_routes import profile_bp
from admin_routes import admin_bp
from upload_routes import upload_bp
from search_routes import search_bp
from webhook_routes import webhook_bp
from import_routes import import_bp
from xml_routes import xml_bp
from render_routes import render_bp
from system_routes import system_bp
from file_routes import file_bp
from cors_routes import cors_bp

app = Flask(__name__)

# VULNERABLE: debug mode left on. Exposes the Werkzeug interactive
# debugger and full stack traces on unhandled errors — an information
# disclosure issue on top of whatever route triggered it.
app.config["DEBUG"] = True

# NOTE: This app intentionally sets no security headers (no CSP, no HSTS,
# no X-Content-Type-Options, etc.) on ANY response, including /health.
# Maps to: Missing / Misconfigured Security Headers (A05:2021 / CWE-1021).
# This is a global characteristic of the app, not a single route, and is
# checked by DAST rules against any endpoint rather than by a dedicated
# route here.

app.register_blueprint(auth_bp)
app.register_blueprint(profile_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(upload_bp)
app.register_blueprint(search_bp)
app.register_blueprint(webhook_bp)
app.register_blueprint(import_bp)
app.register_blueprint(xml_bp)
app.register_blueprint(render_bp)
app.register_blueprint(system_bp)
app.register_blueprint(file_bp)
app.register_blueprint(cors_bp)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "app": "nobreach-vulnerable-api"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
