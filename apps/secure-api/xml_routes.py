from flask import Blueprint, request, jsonify
from lxml import etree

xml_bp = Blueprint("xml_parse", __name__)


@xml_bp.route("/xml/parse", methods=["POST"])
def parse_xml():
    """
    FIXED: XML External Entity Injection (A05:2021 / CWE-611). The
    parser has resolve_entities=False, so a declared external entity
    like <!ENTITY xxe SYSTEM "file:///etc/os-release"> is never fetched
    or substituted. In testing, lxml does not raise an error for this —
    it parses successfully and leaves the entity reference as the
    literal text "&xxe;" in the output, rather than the file's contents.
    Either way, no file content from the server ever reaches the
    response.
    """
    xml_body = request.data
    if not xml_body:
        return jsonify({"error": "xml body required"}), 400

    parser = etree.XMLParser(resolve_entities=False, no_network=True)
    try:
        tree = etree.fromstring(xml_body, parser=parser)
        text_content = "".join(tree.itertext())
        return jsonify({"parsed_text": text_content})
    except etree.XMLSyntaxError as exc:
        return jsonify({"error": str(exc)}), 400
