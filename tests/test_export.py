import json

from qer.models import (AssetProfile, CertInfo, CryptoPrimitive, EndpointReport,
                        Exposure, Finding, QuantumRisk, ScanResult, Scores,
                        Severity, reports_from_document, to_serializable)
from qer.siem.cyclonedx import to_cyclonedx
from qer.siem.json_out import report_to_dict


def _make_report():
    scan = ScanResult(
        host="example.com", port=443, reachable=True, ip="93.184.216.34",
        negotiated_version="TLSv1.3", negotiated_cipher="TLS_AES_256_GCM_SHA384",
        supported_versions=["TLSv1.3", "TLSv1.2"], weak_versions=[],
        key_exchange="ECDHE", authentication="cert", forward_secret=True,
        primitives=[
            CryptoPrimitive(role="protocol", algorithm="TLSv1.3", quantum_risk=QuantumRisk.QUANTUM_VULNERABLE),
            CryptoPrimitive(role="key-exchange", algorithm="ECDHE", quantum_risk=QuantumRisk.QUANTUM_VULNERABLE,
                            forward_secret=True),
            CryptoPrimitive(role="cipher", algorithm="AES-256", quantum_risk=QuantumRisk.PQ_SAFE, bits=256),
        ],
        certificates=[
            CertInfo(subject="CN=example.com", issuer="CN=int", serial="ab", position="leaf",
                     public_key_algorithm="ECDSA", signature_algorithm="ecdsa-with-SHA256",
                     public_key_bits=256, public_key_curve="secp256r1", days_to_expiry=42,
                     not_before="2026-01-01T00:00:00+00:00", not_after="2026-08-01T00:00:00+00:00",
                     sans=["example.com", "www.example.com"], quantum_risk=QuantumRisk.QUANTUM_VULNERABLE),
            CertInfo(subject="CN=int", issuer="CN=root", serial="cd", position="intermediate",
                     public_key_algorithm="ECDSA", signature_algorithm="ecdsa-with-SHA384",
                     public_key_bits=384, quantum_risk=QuantumRisk.QUANTUM_VULNERABLE),
        ],
        pq_testable=True, pq_kex_negotiated=True, pq_groups_supported=["X25519MLKEM768"],
        pq_preferred=False, openssl_version="OpenSSL 3.0.13", scanned_at="2026-06-27T00:00:00+00:00")
    findings = [
        Finding(id="QER-HNDL", title="HNDL", severity=Severity.HIGH,
                quantum_risk=QuantumRisk.QUANTUM_VULNERABLE, category="hndl",
                host="example.com", port=443, description="d", evidence="e",
                recommendation="r", references=["https://x"], location=""),
    ]
    profile = AssetProfile(host="example.com", port=443, label="Web", sensitivity=4,
                           shelf_life_years=10, exposure=Exposure.EXTERNAL, crypto_agility=3,
                           expect_pq=True, notes="n")
    scores = Scores(risk_score=55, hndl_risk=52, migration_difficulty=50, readiness=70, priority="SOON")
    return EndpointReport(profile=profile, scan=scan, findings=findings, scores=scores)


def test_roundtrip_is_lossless():
    reports = [_make_report()]
    doc = json.loads(json.dumps(report_to_dict(reports, {"tool_version": "0.1.0"})))
    restored = reports_from_document(doc)
    assert to_serializable(restored) == to_serializable(reports)


def test_exporters_work_on_restored_reports():
    doc = json.loads(json.dumps(report_to_dict([_make_report()], {"tool_version": "0.1.0"})))
    reports = reports_from_document(doc)
    bom = json.loads(to_cyclonedx(reports))
    assert bom["bomFormat"] == "CycloneDX"
    assert any(c["cryptoProperties"]["assetType"] == "certificate" for c in bom["components"])


def test_rejects_non_qer_document():
    import pytest
    with pytest.raises(ValueError):
        reports_from_document({"not": "a report"})


def test_rejects_non_list_endpoints():
    import pytest
    with pytest.raises(ValueError):
        reports_from_document({"endpoints": "abc"})


def test_skips_non_dict_endpoint_elements():
    assert reports_from_document({"endpoints": [1, None, "x"]}) == []


def test_cli_export_on_garbage_report_is_graceful(tmp_path):
    from qer.cli import main
    bad = tmp_path / "bad.json"
    bad.write_text('{"endpoints":[1,2,3]}', encoding="utf-8")
    assert main(["export", "-i", str(bad), "-f", "stix"]) == 1   # exit 1, not a traceback


def test_enum_from_label_roundtrip():
    for r in QuantumRisk:
        assert QuantumRisk.from_label(r.label) is r
    for s in Severity:
        assert Severity.from_label(s.label) is s
