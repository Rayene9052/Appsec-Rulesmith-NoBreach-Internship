from flask import Blueprint, request, jsonify
from lxml import etree

xml_bp = Blueprint("xml_parse", __name__)


@xml_bp.route("/xml/parse", methods=["POST"])
def parse_xml():
    """
    VULNERABLE: XML External Entity Injection (A05:2021 / CWE-611). The
    parser is configured with resolve_entities=True, so a crafted XML
    document with a DOCTYPE/ENTITY declaration can pull in local file
    contents or trigger further SSRF through the parser itself. A secure
    parser (see apps/secure-api/ in Week 6) disables entity resolution
    and external DTD loading entirely.
    """
    xml_body = request.data
    if not xml_body:
        return jsonify({"error": "xml body required"}), 400

    parser = etree.XMLParser(resolve_entities=True, no_network=False)  # VULNERABLE
    try:
        tree = etree.fromstring(xml_body, parser=parser)
        text_content = "".join(tree.itertext())
        return jsonify({"parsed_text": text_content})
    except etree.XMLSyntaxError as exc:
        return jsonify({"error": str(exc)}), 400
