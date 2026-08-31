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

# FIXED: debug mode is off. No interactive debugger, no stack traces
# leaked in error responses.
app.config["DEBUG"] = False

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


@app.after_request
def set_security_headers(response):
    """
    FIXED: Missing / Misconfigured Security Headers (A05:2021 /
    CWE-1021). Applied globally to every response via after_request, so
    it covers every route including /health without needing to repeat
    this in each route module.
    """
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "app": "nobreach-secure-api"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
