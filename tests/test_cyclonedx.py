import json
import re

from qer.models import (AssetProfile, CertInfo, CryptoPrimitive, EndpointReport,
                        QuantumRisk, ScanResult, Scores)
from qer.siem.cyclonedx import to_cyclonedx

# The exact serialNumber pattern from the CycloneDX 1.6 JSON schema.
_CDX_UUID = re.compile(
    r"^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")

META = {"tool_version": "0.1.0", "generated_at": "2026-06-27T00:00:00+00:00"}


def _report(host="h"):
    prims = [
        CryptoPrimitive(role="protocol", algorithm="TLSv1.3", quantum_risk=QuantumRisk.QUANTUM_VULNERABLE),
        CryptoPrimitive(role="key-exchange", algorithm="ECDHE", quantum_risk=QuantumRisk.QUANTUM_VULNERABLE),
        CryptoPrimitive(role="cipher", algorithm="AES-256", quantum_risk=QuantumRisk.PQ_SAFE),
        CryptoPrimitive(role="mac", algorithm="AEAD", quantum_risk=QuantumRisk.PQ_SAFE),
    ]
    certs = [
        CertInfo(subject="CN=leaf", issuer="CN=int", serial="1", public_key_algorithm="ECDSA",
                 signature_algorithm="ecdsa-with-SHA256", public_key_bits=256, position="leaf",
                 not_before="2024-01-01T00:00:00+00:00", not_after="2030-01-01T00:00:00+00:00",
                 quantum_risk=QuantumRisk.QUANTUM_VULNERABLE),
        CertInfo(subject="CN=int", issuer="CN=root", serial="2", public_key_algorithm="ECDSA",
                 signature_algorithm="ecdsa-with-SHA384", public_key_bits=384, position="intermediate",
                 quantum_risk=QuantumRisk.QUANTUM_VULNERABLE),
    ]
    scan = ScanResult(host=host, port=443, reachable=True, negotiated_version="TLSv1.3",
                      negotiated_cipher="TLS_AES_256_GCM_SHA384", key_exchange="ECDHE",
                      forward_secret=True, primitives=prims, certificates=certs,
                      pq_groups_supported=["X25519MLKEM768"], pq_preferred=False, pq_testable=True)
    return EndpointReport(profile=AssetProfile(host=host), scan=scan, findings=[],
                          scores=Scores(risk_score=1, hndl_risk=1, migration_difficulty=1,
                                        readiness=1, priority="LATER"))


def test_top_level_cyclonedx_structure():
    bom = json.loads(to_cyclonedx([_report()], META))
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["version"] == 1
    assert _CDX_UUID.match(bom["serialNumber"])      # strict RFC-4122 v4, per CDX 1.6 schema
    assert bom["metadata"]["tools"]["components"][0]["name"] == "QER"
    assert bom["metadata"]["timestamp"] == META["generated_at"]


def test_serial_number_is_schema_valid_for_many_inputs():
    # The old raw-hash slicing failed the schema's UUID pattern ~92% of the time.
    for i in range(50):
        bom = json.loads(to_cyclonedx([_report(f"host{i}.example.com")], META))
        assert _CDX_UUID.match(bom["serialNumber"]), bom["serialNumber"]


def test_serial_number_is_deterministic():
    a = json.loads(to_cyclonedx([_report("x")], META))["serialNumber"]
    b = json.loads(to_cyclonedx([_report("x")], META))["serialNumber"]
    assert a == b


def test_components_cover_all_asset_types():
    bom = json.loads(to_cyclonedx([_report()], META))
    types = {c["cryptoProperties"]["assetType"] for c in bom["components"]}
    assert {"algorithm", "certificate", "protocol"} <= types
    assert all(c["type"] == "cryptographic-asset" for c in bom["components"])


def test_certificate_references_resolve():
    bom = json.loads(to_cyclonedx([_report()], META))
    refs = {c["bom-ref"] for c in bom["components"]}
    for c in bom["components"]:
        cp = c["cryptoProperties"]
        if cp["assetType"] == "certificate":
            assert cp["certificateProperties"]["signatureAlgorithmRef"] in refs
            assert cp["certificateProperties"]["subjectPublicKeyRef"] in refs


def test_algorithms_are_deduped_across_endpoints():
    bom = json.loads(to_cyclonedx([_report("a"), _report("b")], META))
    algo_names = [c["name"] for c in bom["components"]
                  if c["cryptoProperties"]["assetType"] == "algorithm"]
    assert algo_names.count("ECDHE") == 1          # shared algorithm emitted once
    assert len(algo_names) == len(set(algo_names))


def test_nist_quantum_level_present_on_algorithms():
    bom = json.loads(to_cyclonedx([_report()], META))
    algs = [c for c in bom["components"] if c["cryptoProperties"]["assetType"] == "algorithm"]
    assert algs and all(
        "nistQuantumSecurityLevel" in a["cryptoProperties"]["algorithmProperties"] for a in algs)
    # X25519MLKEM768 would be PQ; ECDHE is classical -> level 0
    ecdhe = next(a for a in algs if a["name"] == "ECDHE")
    assert ecdhe["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0


def test_no_explicit_nulls_in_output():
    raw = to_cyclonedx([_report()], META)
    assert "null" not in raw          # _prune drops every None


def test_bom_refs_unique_for_duplicate_reports():
    # Same host:port appearing twice (duplicate target / merged report) must not
    # produce colliding bom-refs.
    bom = json.loads(to_cyclonedx([_report("a"), _report("a")], META))
    refs = [c["bom-ref"] for c in bom["components"]]
    assert len(refs) == len(set(refs))


def test_empty_cert_algorithms_do_not_conflate():
    scan = ScanResult(host="h", port=443, reachable=True, negotiated_version="TLSv1.3",
                      certificates=[CertInfo(subject="s", issuer="i", serial="1", position="leaf",
                          public_key_algorithm="", signature_algorithm="",
                          quantum_risk=QuantumRisk.QUANTUM_VULNERABLE)])
    rep = EndpointReport(profile=AssetProfile(host="h"), scan=scan, findings=[],
                         scores=Scores(risk_score=1, hndl_risk=1, migration_difficulty=1,
                                       readiness=1, priority="OK"))
    bom = json.loads(to_cyclonedx([rep], META))
    cert = next(c for c in bom["components"]
                if c["cryptoProperties"].get("assetType") == "certificate")
    cp = cert["cryptoProperties"]["certificateProperties"]
    assert cp["signatureAlgorithmRef"] != cp["subjectPublicKeyRef"]   # not collapsed to one
    refs = [c["bom-ref"] for c in bom["components"]]
    assert len(refs) == len(set(refs))


def test_code_cbom_from_fixture():
    import os

    from qer.codescan import scan_path
    from qer.siem.cyclonedx import code_to_cyclonedx
    fixture = os.path.join(os.path.dirname(__file__), "fixtures", "sample_app")
    report = scan_path(fixture)
    raw = code_to_cyclonedx(report, META)
    bom = json.loads(raw)
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    assert _CDX_UUID.match(bom["serialNumber"])
    types = {c["type"] for c in bom["components"]}
    assert "cryptographic-asset" in types and "library" in types     # algorithms + crypto deps
    algs = [c for c in bom["components"]
            if c.get("cryptoProperties", {}).get("assetType") == "algorithm"]
    assert algs
    occ = algs[0]["evidence"]["occurrences"]
    assert occ and ":" in occ[0]["location"]                          # file:line evidence
    assert "nistQuantumSecurityLevel" in algs[0]["cryptoProperties"]["algorithmProperties"]
    assert "null" not in raw
    refs = [c["bom-ref"] for c in bom["components"]]
    assert len(refs) == len(set(refs))               # all bom-refs unique (CDX requires it)


def test_code_cbom_material_refs_unique_for_slug_colliding_paths():
    # Two private keys at paths that slug identically must not collide on bom-ref.
    from qer.codescan import CodeReport
    from qer.models import Finding, QuantumRisk, Severity
    from qer.siem.cyclonedx import code_to_cyclonedx
    mk = lambda loc: Finding(id="QER-CODE-PRIVKEY", title="key", severity=Severity.HIGH,
                             quantum_risk=QuantumRisk.QUANTUM_VULNERABLE, category="secret",
                             host="(code)", port=0, description="hardcoded key", location=loc)
    report = CodeReport(root="r", files_scanned=2,
                        findings=[mk("keys/prod.pem:1"), mk("keys-prod.pem:1")])
    bom = json.loads(code_to_cyclonedx(report, META))
    refs = [c["bom-ref"] for c in bom["components"]]
    assert len(refs) == len(set(refs)) == 2
