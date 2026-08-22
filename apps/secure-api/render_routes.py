from flask import Blueprint, request, jsonify
from jinja2 import Template

render_bp = Blueprint("render_greeting", __name__)

# FIXED: the template SOURCE is a fixed literal, defined once, never
# built from user input. "name" is passed in only as render *data*, so
# template syntax inside it (e.g. "{{ 7*7 }}") is displayed as inert
# text instead of being compiled and executed.
GREETING_TEMPLATE = Template("Hello, {{ name }}!")


@render_bp.route("/render", methods=["POST"])
def render_greeting():
    data = request.get_json(force=True, silent=True) or {}
    name = data.get("name", "world")
    rendered = GREETING_TEMPLATE.render(name=name)
    return jsonify({"message": rendered})
