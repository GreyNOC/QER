"""Coverage for the console renderers, JSON/detection exporters, and the CLI
command handlers — the pure (non-network) code that the per-feature tests left
under-covered."""

import json
import os

from qer.models import (AssetProfile, CertInfo, CryptoPrimitive, EndpointReport,
                        Exposure, Finding, QuantumRisk, ScanResult, Scores, Severity)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
META = {"tool_version": "0.1.0", "openssl": "OpenSSL 3.0", "generated_at": "2026-06-28T00:00:00+00:00"}


def _report(host="example.com", reachable=True):
    scan = ScanResult(
        host=host, port=443, reachable=reachable, error=None if reachable else "timeout",
        negotiated_version="TLSv1.3" if reachable else None,
        negotiated_cipher="TLS_AES_256_GCM_SHA384", key_exchange="ECDHE",
        forward_secret=True, weak_versions=["TLSv1.0"],
        primitives=[CryptoPrimitive(role="cipher", algorithm="AES-256",
                                    quantum_risk=QuantumRisk.PQ_SAFE, bits=256)],
        certificates=[CertInfo(subject="CN=example.com", issuer="CN=ca", serial="1", position="leaf",
                               public_key_algorithm="ECDSA", signature_algorithm="ecdsa-with-SHA256",
                               public_key_bits=256, days_to_expiry=20,
                               quantum_risk=QuantumRisk.QUANTUM_VULNERABLE)] if reachable else [],
        pq_testable=True, pq_groups_supported=["X25519MLKEM768"], pq_preferred=False)
    findings = [Finding(id="QER-HNDL", title="HNDL exposure", severity=Severity.HIGH,
                        quantum_risk=QuantumRisk.QUANTUM_VULNERABLE, category="hndl",
                        host=host, port=443, description="d", evidence="e", recommendation="r")] if reachable else []
    scores = (Scores(risk_score=79, hndl_risk=52, migration_difficulty=50, readiness=70, priority="NOW")
              if reachable else None)
    return EndpointReport(profile=AssetProfile(host=host, label="Web", exposure=Exposure.EXTERNAL),
                          scan=scan, findings=findings, scores=scores)


# ----------------------------- renderers ----------------------------------- #

def test_render_console_covers_map_and_cbom_and_unreachable():
    from qer.report import render_console
    out = render_console([_report(), _report("down.example.com", reachable=False)], META, color=False)
    assert "example.com:443" in out
    assert "EXECUTIVE MIGRATION MAP" in out
    assert "CRYPTOGRAPHIC BILL OF MATERIALS" in out
    assert "UNREACHABLE" in out
    assert "legacy accepted" in out          # weak_versions branch


def test_render_console_emits_ansi_when_color():
    from qer.report import render_console
    assert "\033[" in render_console([_report()], META, color=True)


def test_render_code_console():
    from qer.codescan import scan_path
    from qer.report import render_code_console
    out = render_code_console(scan_path(os.path.join(FIXTURES, "sample_app")), META, color=False)
    assert "code scan" in out.lower() and "Findings" in out


def test_render_passive_console():
    from qer.passive import measure
    from qer.report import render_passive_console
    out = render_passive_console(measure(os.path.join(FIXTURES, "ssl_tsv.log")), META, color=False)
    assert "POST-QUANTUM COVERAGE" in out and "api.example.com" in out


def test_render_ike_console():
    from qer.ikescan import IkeResult, classify, generate_ike_findings
    from qer.report import render_ike_console
    r = IkeResult(host="vpn", port=500, reachable=True, ike_version="2.0", responder=True,
                  chosen={"dh-group": {"id": 2, "name": "MODP-1024", "keylen": None}})
    classify(r)
    r.findings = generate_ike_findings(r)
    out = render_ike_console(r, META, color=False)
    assert "IKE / IPsec scan" in out and "MODP-1024" in out
    # unreachable path
    bad = render_ike_console(IkeResult(host="v", port=500, reachable=False, error="timeout"), META, color=False)
    assert "no IKE response" in bad


# ----------------------------- json_out ------------------------------------ #

def test_json_out_full_and_feed():
    from qer.siem import json_out
    reps = [_report()]
    doc = json.loads(json_out.to_json(reps, META))
    assert doc["tool"] == "qer" and len(doc["endpoints"]) == 1
    events = json_out.finding_events(reps)
    assert events[0]["finding_id"] == "QER-HNDL" and events[0]["host"] == "example.com"
    assert json.loads(json_out.to_ndjson(reps, META).splitlines()[0])["finding_id"] == "QER-HNDL"


def test_json_out_code_and_passive_feeds():
    from qer.codescan import scan_path
    from qer.passive import measure
    from qer.siem import json_out
    code = scan_path(os.path.join(FIXTURES, "sample_app"))
    assert json.loads(json_out.code_to_json(code, META))["scan_type"] == "code"
    code_ev = json_out.code_finding_events(code)
    assert code_ev and "location" in code_ev[0]
    assert json.loads(json_out.code_to_ndjson(code, META).splitlines()[0])["scan_type"] == "code"
    pas = measure(os.path.join(FIXTURES, "ssl_tsv.log"))
    assert json.loads(json_out.passive_to_json(pas, META))["scan_type"] == "passive"
    assert "service" in json_out.passive_finding_events(pas)[0]
    assert json.loads(json_out.passive_to_ndjson(pas, META).splitlines()[0])["scan_type"] == "passive"


# ----------------------------- detection content --------------------------- #

def test_detection_exporters_emit_expected_content():
    from qer.siem import kql, sigma, splunk, zeek
    reps = [_report()]                       # carries an hndl finding
    s = sigma.to_sigma(reps, META)
    assert "product: qer" in s and "product: zeek" in s and "hndl" in s
    assert "sourcetype" in splunk.to_splunk(reps, META)
    assert "QER_CL" in kql.to_kql(reps, META)
    assert "event ssl_established" in zeek.to_zeek(reps, META)


# ----------------------------- CLI ----------------------------------------- #

def test_cli_parser_wires_every_subcommand():
    from qer.cli import build_parser
    p = build_parser()
    for args in (["scan", "h"], ["code", "p"], ["passive", "l"], ["export", "-i", "r.json"], ["ike", "h"]):
        assert getattr(p.parse_args(args), "func", None) is not None, args
    assert getattr(p.parse_args([]), "func", None) is None


def test_cli_main_code_writes_json(tmp_path):
    from qer.cli import main
    out = tmp_path / "r.json"
    rc = main(["code", os.path.join(FIXTURES, "sample_app"), "--json", str(out), "--no-color"])
    assert rc == 0 and out.exists()
    assert json.loads(out.read_text(encoding="utf-8"))["scan_type"] == "code"


def test_cli_main_export_roundtrips(tmp_path):
    from qer.cli import main
    from qer.siem.json_out import to_json
    rep = tmp_path / "rep.json"
    rep.write_text(to_json([_report()], META), encoding="utf-8")
    cbom = tmp_path / "cbom.json"
    rc = main(["export", "-i", str(rep), "-f", "cyclonedx", "-o", str(cbom)])
    assert rc == 0
    assert json.loads(cbom.read_text(encoding="utf-8"))["bomFormat"] == "CycloneDX"


def test_cli_main_no_args_prints_help(capsys):
    from qer.cli import main
    assert main([]) == 0
    assert "usage:" in capsys.readouterr().out.lower()


def test_cli_main_passive_fail_on(tmp_path):
    from qer.cli import main
    # passive on the fixture has a LOW partial finding -> fail-on low returns 2
    rc = main(["passive", os.path.join(FIXTURES, "ssl_tsv.log"), "--fail-on", "low", "--no-color"])
    assert rc == 2
