from qer.downgrade import compare, snapshot
from qer.models import CertInfo, CryptoPrimitive, ScanResult


def scan(version="TLSv1.3", weak=None, kex="ECDHE", fs=True,
         cipher="TLS_AES_256_GCM_SHA384", cipher_bits=256, cert_bits=256,
         pq=None, pq_testable=True, pq_preferred=None):
    return ScanResult(
        host="h", port=443, reachable=True, negotiated_version=version,
        negotiated_cipher=cipher, key_exchange=kex, forward_secret=fs,
        weak_versions=weak or [], supported_versions=[version] + (weak or []),
        primitives=[CryptoPrimitive(role="cipher", algorithm=cipher, bits=cipher_bits)],
        certificates=[CertInfo(subject="s", issuer="i", serial="01",
                               public_key_algorithm="ECDSA",
                               signature_algorithm="ecdsa-with-SHA256",
                               public_key_bits=cert_bits)],
        pq_kex_negotiated=pq, pq_testable=pq_testable, pq_preferred=pq_preferred)


def ids(prev_scan, new_scan):
    return {f.id for f in compare(new_scan, snapshot(prev_scan))}


def test_no_change_no_findings():
    assert ids(scan(), scan()) == set()


def test_protocol_downgrade():
    assert "QER-DG-PROTO" in ids(scan(version="TLSv1.3"), scan(version="TLSv1.2"))


def test_forward_secrecy_lost():
    assert "QER-DG-FS" in ids(scan(kex="ECDHE", fs=True), scan(kex="RSA", fs=False))


def test_pq_downgrade_is_critical():
    # A genuine downgrade: PQ was negotiated before, now actively tested as gone.
    findings = compare(scan(pq=False), snapshot(scan(pq=True)))
    pq = [f for f in findings if f.id == "QER-DG-PQ"]
    assert pq and pq[0].severity.label == "critical"


def test_no_pq_rescan_does_not_false_alarm():
    # Re-scanning with --no-pq leaves PQ untested (None) -> must NOT page a downgrade.
    findings = compare(scan(pq=None, pq_testable=False), snapshot(scan(pq=True)))
    assert "QER-DG-PQ" not in {f.id for f in findings}


def test_pq_enforcement_relaxation_flagged():
    # Still supports PQ, but no longer enforces it (enforce -> tolerate).
    findings = compare(scan(pq=True, pq_preferred=False),
                       snapshot(scan(pq=True, pq_preferred=True)))
    assert "QER-DG-PQ-ENFORCE" in {f.id for f in findings}


def test_new_legacy_version_accepted():
    assert "QER-DG-LEGACY" in ids(scan(weak=[]), scan(weak=["TLSv1.0"]))


def test_cipher_strength_reduced():
    assert "QER-DG-CIPHER" in ids(scan(cipher_bits=256), scan(cipher_bits=128))


def test_certificate_key_shrunk():
    assert "QER-DG-KEY" in ids(scan(cert_bits=4096), scan(cert_bits=2048))


def test_improvement_is_not_flagged():
    # Going from TLS1.2 -> TLS1.3 must not raise a downgrade.
    assert "QER-DG-PROTO" not in ids(scan(version="TLSv1.2"), scan(version="TLSv1.3"))
