from flask import Blueprint, request, jsonify
from jinja2 import Template

render_bp = Blueprint("render_greeting", __name__)


@render_bp.route("/render", methods=["POST"])
def render_greeting():
    """
    VULNERABLE: Server-Side Template Injection (A03:2021 / CWE-1336). The
    "name" field is spliced directly into a template string and compiled
    with Jinja2, instead of being passed in as template *data*. Template
    syntax in the input — like {{ 7*7 }} — gets evaluated server-side,
    and a more advanced payload can escape the sandbox to run arbitrary
    Python.
    """
    data = request.get_json(force=True, silent=True) or {}
    name = data.get("name", "world")

    template = Template(f"Hello, {name}!")  # VULNERABLE: user input in template source
    rendered = template.render()
    return jsonify({"message": rendered})
