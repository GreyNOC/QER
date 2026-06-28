from qer.classify import classify_protocol, classify_public_key, is_pq_algorithm
from qer.models import (AssetProfile, CertInfo, CryptoPrimitive, Exposure,
                        QuantumRisk, ScanResult)
from qer.scoring import generate_findings, hndl_risk, score_endpoint


def make_scan(kex="ECDHE", fs=True, version="TLSv1.3", weak=None,
              cipher="TLS_AES_256_GCM_SHA384", cipher_bits=256,
              cipher_risk=QuantumRisk.PQ_SAFE, cert_days=120,
              cert_alg="ECDSA", cert_bits=256, reachable=True, pq_negotiated=None):
    prims = [
        CryptoPrimitive(role="protocol", algorithm=version,
                        quantum_risk=classify_protocol(version)[0]),
        CryptoPrimitive(role="key-exchange", algorithm=kex, forward_secret=fs,
                        quantum_risk=QuantumRisk.PQ_SAFE if is_pq_algorithm(kex)
                        else QuantumRisk.QUANTUM_VULNERABLE),
        CryptoPrimitive(role="cipher", algorithm=cipher, quantum_risk=cipher_risk, bits=cipher_bits),
        CryptoPrimitive(role="mac", algorithm="AEAD", quantum_risk=QuantumRisk.PQ_SAFE),
    ]
    for w in (weak or []):
        prims.append(CryptoPrimitive(role="protocol", algorithm=w, quantum_risk=QuantumRisk.BROKEN_NOW))
    certs = []
    if cert_alg:
        certs.append(CertInfo(
            subject="CN=test", issuer="CN=ca", serial="01",
            public_key_algorithm=cert_alg, signature_algorithm="ecdsa-with-SHA256",
            public_key_bits=cert_bits, days_to_expiry=cert_days,
            not_after="2030-01-01T00:00:00+00:00",
            quantum_risk=classify_public_key(cert_alg, cert_bits)[0]))
    return ScanResult(
        host="h", port=443, reachable=reachable, negotiated_version=version,
        negotiated_cipher=cipher, key_exchange=kex, forward_secret=fs,
        supported_versions=[version] + (weak or []), weak_versions=weak or [],
        primitives=prims, certificates=certs, pq_kex_negotiated=pq_negotiated)


def test_hndl_worst_case_is_rsa_no_fs_long_shelf():
    p = AssetProfile(host="h", sensitivity=5, shelf_life_years=15, exposure=Exposure.EXTERNAL)
    scan = make_scan(kex="RSA", fs=False)
    assert hndl_risk(p, scan) == 100


def test_hndl_ecdhe_is_high_but_below_no_fs():
    p = AssetProfile(host="h", sensitivity=5, shelf_life_years=15, exposure=Exposure.EXTERNAL)
    assert hndl_risk(p, make_scan(kex="ECDHE", fs=True)) == 80


def test_hndl_zero_for_pq_kex():
    p = AssetProfile(host="h", sensitivity=5, shelf_life_years=15, exposure=Exposure.EXTERNAL)
    assert hndl_risk(p, make_scan(kex="X25519MLKEM768", fs=True)) == 0


def test_proven_pq_support_sharply_reduces_hndl():
    p = AssetProfile(host="h", sensitivity=5, shelf_life_years=15, exposure=Exposure.EXTERNAL)
    classical = make_scan(kex="ECDHE", fs=True)
    pq = make_scan(kex="ECDHE", fs=True, pq_negotiated=True)
    assert hndl_risk(p, pq) < hndl_risk(p, classical)
    assert hndl_risk(p, pq) <= 20


def test_pq_enforced_beats_pq_tolerated():
    p = AssetProfile(host="h", sensitivity=5, shelf_life_years=15, exposure=Exposure.EXTERNAL)
    tolerated = make_scan(kex="ECDHE", fs=True, pq_negotiated=True)        # supported, not enforced
    enforced = make_scan(kex="ECDHE", fs=True, pq_negotiated=True)
    enforced.pq_preferred = True
    assert hndl_risk(p, enforced) < hndl_risk(p, tolerated)


def test_pq_ok_finding_emitted_when_supported():
    p = AssetProfile(host="h")
    scan = make_scan(kex="ECDHE", fs=True, pq_negotiated=True)
    scan.pq_testable = True
    scan.pq_groups_supported = ["X25519MLKEM768"]
    scores = score_endpoint(p, scan)
    assert "QER-PQ-OK" in {f.id for f in generate_findings(p, scan, scores)}


def test_pq_missing_finding_when_expected_but_absent():
    p = AssetProfile(host="h", expect_pq=True)
    scan = make_scan(kex="ECDHE", fs=True)
    scan.pq_testable = True            # probe ran, found nothing
    scores = score_endpoint(p, scan)
    assert "QER-PQ-MISSING" in {f.id for f in generate_findings(p, scan, scores)}


def test_certificate_chain_findings():
    leaf = CertInfo(subject="CN=leaf", issuer="CN=int", serial="1",
                    public_key_algorithm="ECDSA", signature_algorithm="ecdsa-with-SHA256",
                    public_key_bits=256, position="leaf", days_to_expiry=200,
                    quantum_risk=QuantumRisk.QUANTUM_VULNERABLE)
    inter = CertInfo(subject="CN=int", issuer="CN=root", serial="2",
                     public_key_algorithm="RSA", signature_algorithm="sha1WithRSAEncryption",
                     public_key_bits=2048, position="intermediate", days_to_expiry=1000,
                     quantum_risk=QuantumRisk.BROKEN_NOW)
    p = AssetProfile(host="h")
    scan = make_scan()
    scan.certificates = [leaf, inter]
    findings = generate_findings(p, scan, score_endpoint(p, scan))
    ids = [f.id for f in findings]
    assert "QER-CHAIN-CBOM" in ids                 # full-chain inventory
    assert "QER-CHAIN-WEAK" in ids                 # SHA-1 intermediate flagged
    assert ids.count("QER-CERT-PQ") == 1           # leaf only, not one per cert


def test_hndl_scales_down_for_internal_low_sensitivity():
    p = AssetProfile(host="h", sensitivity=1, shelf_life_years=1, exposure=Exposure.INTERNAL)
    assert hndl_risk(p, make_scan()) < 25


def test_legacy_tls_forces_now_priority():
    p = AssetProfile(host="h", sensitivity=3, shelf_life_years=5)
    scores = score_endpoint(p, make_scan(weak=["TLSv1.0", "TLSv1.1"]))
    assert scores.priority == "NOW"
    assert scores.risk_score >= 70


def test_unreachable_endpoint_scores_unreachable():
    p = AssetProfile(host="h")
    scores = score_endpoint(p, ScanResult(host="h", port=443, reachable=False, error="timeout"))
    assert scores.priority == "UNREACHABLE"
    assert scores.risk_score == 0


def test_migration_difficulty_tracks_inverse_agility():
    p_easy = AssetProfile(host="h", crypto_agility=5)
    p_hard = AssetProfile(host="h", crypto_agility=1)
    scan = make_scan()
    assert score_endpoint(p_easy, scan).migration_difficulty < score_endpoint(p_hard, scan).migration_difficulty


def test_findings_flag_legacy_and_no_fs_and_expiry():
    p = AssetProfile(host="h", sensitivity=4, shelf_life_years=10)
    scan = make_scan(kex="RSA", fs=False, weak=["TLSv1.0"], cert_days=-3)
    scores = score_endpoint(p, scan)
    ids = {f.id for f in generate_findings(p, scan, scores)}
    assert "QER-PROTO-LEGACY" in ids
    assert "QER-NOFS" in ids
    assert "QER-CERT-EXPIRED" in ids
    assert "QER-HNDL" in ids


def test_expect_pq_unverified_finding_when_not_testable():
    p = AssetProfile(host="h", expect_pq=True)
    scan = make_scan()           # pq_testable defaults to False
    scores = score_endpoint(p, scan)
    assert "QER-PQ-UNVERIFIED" in {f.id for f in generate_findings(p, scan, scores)}
