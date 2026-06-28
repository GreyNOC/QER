import json
import re

from qer.models import (AssetProfile, CertInfo, CryptoPrimitive, EndpointReport,
                        Exposure, Finding, QuantumRisk, ScanResult, Scores, Severity)
from qer.siem.html_report import to_html

META = {"tool_version": "0.1.0", "generated_at": "2026-06-27T00:00:00+00:00",
        "openssl": "OpenSSL 3.0.13"}


def _report(subject="CN=example.com", reachable=True):
    scan = ScanResult(
        host="example.com", port=443, reachable=reachable,
        negotiated_version="TLSv1.3", negotiated_cipher="TLS_AES_256_GCM_SHA384",
        key_exchange="ECDHE", forward_secret=True, weak_versions=["TLSv1.0"],
        primitives=[CryptoPrimitive(role="cipher", algorithm="AES-256", quantum_risk=QuantumRisk.PQ_SAFE)],
        certificates=[CertInfo(subject=subject, issuer="CN=int", serial="1", position="leaf",
                               public_key_algorithm="ECDSA", signature_algorithm="ecdsa-with-SHA256",
                               public_key_bits=256, days_to_expiry=40,
                               quantum_risk=QuantumRisk.QUANTUM_VULNERABLE)],
        pq_testable=True, pq_groups_supported=["X25519MLKEM768"], pq_preferred=False)
    findings = [Finding(id="QER-HNDL", title="HNDL exposure", severity=Severity.HIGH,
                        quantum_risk=QuantumRisk.QUANTUM_VULNERABLE, category="hndl",
                        host="example.com", port=443, description="d",
                        references=["https://csrc.nist.gov/projects/post-quantum-cryptography"])]
    return EndpointReport(profile=AssetProfile(host="example.com", label="Web", exposure=Exposure.EXTERNAL),
                          scan=scan, findings=findings,
                          scores=Scores(risk_score=79, hndl_risk=52, migration_difficulty=50,
                                        readiness=70, priority="NOW"))


def _extract_json(html):
    m = re.search(r'<script id="qer-data" type="application/json">(.*?)</script>', html, re.S)
    assert m, "embedded data script not found"
    return json.loads(m.group(1).replace("<\\/", "</"))


def test_is_self_contained_html():
    html = to_html([_report()], META)
    assert html.lstrip().startswith("<!doctype html>")
    low = html.lower()
    assert "src=" not in low          # no external scripts/images
    assert "<link" not in low         # no external stylesheets
    assert "@import" not in low        # no CSS imports


def test_embedded_json_parses_and_has_data():
    data = _extract_json(to_html([_report()], META))
    assert data["meta"]["endpoints"] == 1
    assert data["endpoints"][0]["scan"]["host"] == "example.com"
    assert data["migration"][0]["priority"] == "NOW"


def test_renderer_never_uses_innerhtml():
    # textContent-only rendering is the XSS guarantee.
    assert "innerHTML" not in to_html([_report()], META)


def test_attacker_data_cannot_break_or_inject_script_elements():
    # Includes the script-data-double-escape gadget (<!--<script>) that a
    # naive </-only escape misses and which would swallow the renderer.
    gadgets = ["</script><script>alert(1)</script>", "<!--<script>",
               "<!--<script>-->", "</SCRIPT\t>", "x<!--<script>y</script>z"]
    for g in gadgets:
        html = to_html([_report(subject=g)], META)
        # exactly two <script> elements survive: the data blob + the renderer
        assert html.count("<script") == 2, g
        assert "<!--<script" not in html
        assert "</script><script>alert" not in html
        # ...and the value still round-trips losslessly through the embedded JSON
        assert _extract_json(html)["endpoints"][0]["scan"]["certificates"][0]["subject"] == g


def test_unreachable_endpoint_renders():
    html = to_html([_report(reachable=False)], META)
    assert "<!doctype html>" in html.lower()
    assert _extract_json(html)["endpoints"][0]["scan"]["reachable"] is False
