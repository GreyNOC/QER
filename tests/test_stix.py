import json
import re

from qer.models import (AssetProfile, CertInfo, EndpointReport, Finding,
                        QuantumRisk, ScanResult, Scores, Severity)
from qer.siem.stix import to_stix

META = {"tool_version": "0.1.0", "generated_at": "2026-06-27T22:39:51.040561+00:00"}

_ID = re.compile(r"^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")


def _report():
    scan = ScanResult(host="example.com", port=443, reachable=True,
                      negotiated_version="TLSv1.3", negotiated_cipher="TLS_AES_256_GCM_SHA384",
                      certificates=[CertInfo(subject="CN=example.com", issuer="CN=ca", serial="1",
                          public_key_algorithm="ECDSA", signature_algorithm="ecdsa-with-SHA256",
                          position="leaf", quantum_risk=QuantumRisk.QUANTUM_VULNERABLE)])
    findings = [
        Finding(id="QER-HNDL", title="HNDL exposure", severity=Severity.HIGH,
                quantum_risk=QuantumRisk.QUANTUM_VULNERABLE, category="hndl",
                host="example.com", port=443, description="harvest now decrypt later",
                evidence="kex=ECDHE", recommendation="adopt hybrid PQ",
                references=["https://csrc.nist.gov/projects/post-quantum-cryptography"]),
        Finding(id="QER-CERT-PQ", title="Quantum-vulnerable certificate", severity=Severity.MEDIUM,
                quantum_risk=QuantumRisk.QUANTUM_VULNERABLE, category="pqc",
                host="example.com", port=443, description="ECDSA leaf"),
        Finding(id="QER-CHAIN-CBOM", title="Chain inventory", severity=Severity.INFO,
                quantum_risk=QuantumRisk.QUANTUM_VULNERABLE, category="inventory",
                host="example.com", port=443, description="3 certs"),
    ]
    return EndpointReport(profile=AssetProfile(host="example.com"), scan=scan, findings=findings,
                          scores=Scores(risk_score=55, hndl_risk=52, migration_difficulty=50,
                                        readiness=70, priority="SOON"))


def test_bundle_shape():
    b = json.loads(to_stix([_report()], META))
    assert b["type"] == "bundle"
    assert b["id"].startswith("bundle--") and _ID.match(b["id"])
    assert isinstance(b["objects"], list) and b["objects"]
    assert "spec_version" not in b           # bundle has no spec_version in STIX 2.1


def test_every_sdo_well_formed():
    objs = json.loads(to_stix([_report()], META))["objects"]
    for o in objs:
        assert _ID.match(o["id"]), o["id"]
        assert o["id"].split("--")[0] == o["type"]
        assert o["spec_version"] == "2.1"
        assert _TS.match(o["created"]) and _TS.match(o["modified"])


def test_producer_identity_present():
    objs = json.loads(to_stix([_report()], META))["objects"]
    ids = [o for o in objs if o["type"] == "identity" and o["name"].startswith("GreyNOC")]
    assert ids and ids[0]["identity_class"] == "system"


def test_info_findings_excluded_actionable_mapped():
    objs = json.loads(to_stix([_report()], META))["objects"]
    vulns = [o for o in objs if o["type"] == "vulnerability"]
    names = {v["name"] for v in vulns}
    assert "HNDL exposure" in names and "Quantum-vulnerable certificate" in names
    assert "Chain inventory" not in names           # INFO finding is omitted


def test_reference_integrity_and_external_refs():
    objs = json.loads(to_stix([_report()], META))["objects"]
    ids = {o["id"] for o in objs}
    for o in objs:
        for ref_field in ("created_by_ref", "source_ref", "target_ref"):
            if ref_field in o:
                assert o[ref_field] in ids, (o["type"], ref_field)
        for er in o.get("external_references", []):
            assert "source_name" in er
    rels = [o for o in objs if o["type"] == "relationship"]
    assert rels and all(r["relationship_type"] == "related-to" for r in rels)


def test_custom_properties_prefixed_and_no_nulls():
    raw = to_stix([_report()], META)
    assert "null" not in raw                         # _prune drops None
    objs = json.loads(raw)["objects"]
    for o in objs:
        for k in o:
            if k not in ("type", "spec_version", "id", "created", "modified", "name",
                         "description", "identity_class", "created_by_ref", "labels",
                         "external_references", "relationship_type", "source_ref", "target_ref"):
                assert k.startswith("x_"), k


def test_deterministic():
    assert to_stix([_report()], META) == to_stix([_report()], META)


def test_timestamp_always_valid_utc_z():
    from qer.siem.stix import _stix_ts
    # a non-UTC offset is converted to true UTC, never emitted as offset+Z
    assert _stix_ts({"generated_at": "2026-06-27T22:39:51+05:30"}) == "2026-06-27T17:09:51.000Z"
    for v in ["2026-06-27T22:39:51.040561+00:00", "2026-06-27T22:39:51-05:00",
              "2026-06-27T22:39:51", "2026-06-27T22:39:51Z", "not-a-date", ""]:
        out = _stix_ts({"generated_at": v})
        assert _TS.match(out), (v, out)        # always a valid STIX UTC timestamp


def test_labels_omit_empty_category():
    rep = _report()
    rep.findings[0] = Finding(id="X", title="t", severity=Severity.HIGH,
                              quantum_risk=QuantumRisk.QUANTUM_VULNERABLE, category="",
                              host="example.com", port=443, description="d")
    objs = json.loads(to_stix([rep], META))["objects"]
    vuln = next(o for o in objs if o["type"] == "vulnerability")
    assert "" not in vuln["labels"] and vuln["labels"] == ["quantum-vulnerable"]
