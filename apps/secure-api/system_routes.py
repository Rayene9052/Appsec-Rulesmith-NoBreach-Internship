import os
import re
import subprocess
from flask import Blueprint, request, jsonify

system_bp = Blueprint("system_routes", __name__)

# Strict regex allowlist for hostnames and IPv4 addresses: only letters, digits, dots, hyphens
HOST_PATTERN = re.compile(r"^[a-zA-Z0-9.-]+$")


@system_bp.route("/system/ping", methods=["POST"])
def ping_host():
    """
    FIXED: OS Command Injection (A03:2021 / CWE-78).
    
    1. Enforces strict regex validation on the input host parameter, rejecting
       any shell metacharacters (';', '&&', '|', '`', '$', etc.) or whitespace.
    2. Uses subprocess with shell=False, passing arguments as a fixed list so
       the operating system shell is never invoked to parse or execute commands.
    """
    data = request.get_json(force=True, silent=True) or {}
    host = data.get("host", "").strip()

    if not host:
        return jsonify({"error": "Host parameter is required"}), 400

    # Validation: Reject any input that does not strictly match hostname/IP pattern
    if not HOST_PATTERN.match(host) or " " in host or ";" in host or "&" in host or "|" in host:
        return jsonify({
            "error": "Invalid host format. Shell metacharacters are strictly rejected."
        }), 400

    # FIXED: shell=False with argument list. No shell parsing occurs.
    ping_cmd = ["ping", "-n", "1", host] if os.name == "nt" else ["ping", "-c", "1", host]

    try:
        output = subprocess.check_output(ping_cmd, shell=False, text=True, timeout=5)
    except subprocess.CalledProcessError as exc:
        output = exc.output or f"Ping failed with return code {exc.returncode}"
    except Exception as exc:
        output = str(exc)

    return jsonify({
        "status": "completed",
        "host": host,
        "output": output
    })
