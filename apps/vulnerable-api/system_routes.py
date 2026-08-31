import os
import subprocess
from flask import Blueprint, request, jsonify

system_bp = Blueprint("system_routes", __name__)


@system_bp.route("/system/ping", methods=["POST"])
def ping_host():
    """
    VULNERABLE: OS Command Injection (A03:2021 / CWE-78). The user-supplied
    "host" parameter is interpolated directly into a shell command and
    executed via subprocess with shell=True.

    An attacker can supply shell metacharacters (e.g. ';', '&&', '|') to
    chain and execute arbitrary operating system commands with the privileges
    of the web server process.
    """
    data = request.get_json(force=True, silent=True) or {}
    host = data.get("host", "127.0.0.1")

    # VULNERABLE: Direct string interpolation into shell command executed with shell=True
    cmd = f"ping -c 1 {host} 2>&1" if os.name != "nt" else f"ping -n 1 {host}"

    try:
        output = subprocess.check_output(cmd, shell=True, text=True, timeout=5)
    except subprocess.CalledProcessError as exc:
        output = exc.output or str(exc)
    except Exception as exc:
        output = str(exc)

    return jsonify({
        "status": "completed",
        "host": host,
        "output": output
    })
