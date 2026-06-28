from qer.classify import (classify_protocol, classify_public_key,
                          classify_signature, is_pq_algorithm, is_weak_protocol,
                          parse_cipher)
from qer.models import QuantumRisk


def test_ecdhe_suite_is_forward_secret_but_quantum_vulnerable():
    p = parse_cipher("ECDHE-RSA-AES256-GCM-SHA384")
    assert p.key_exchange == "ECDHE"
    assert p.forward_secret is True
    assert p.cipher == "AES-256"
    # The ECDHE key exchange dominates: AES-256 is fine, but the handshake is HNDL-exposed.
    assert p.quantum_risk == QuantumRisk.QUANTUM_VULNERABLE


def test_rsa_key_transport_has_no_forward_secrecy():
    p = parse_cipher("AES128-GCM-SHA256")
    assert p.key_exchange == "RSA"
    assert p.forward_secret is False


def test_tls13_suite_name_implies_ephemeral_kex():
    p = parse_cipher("TLS_CHACHA20_POLY1305_SHA256")
    assert p.forward_secret is True
    assert p.cipher == "ChaCha20-Poly1305"
    assert p.key_exchange == "ECDHE"


def test_3des_is_broken_now():
    assert parse_cipher("DES-CBC3-SHA").quantum_risk == QuantumRisk.BROKEN_NOW


def test_sha1_mac_makes_suite_broken_now():
    assert parse_cipher("ECDHE-RSA-AES128-SHA").quantum_risk == QuantumRisk.BROKEN_NOW


def test_aes128_is_quantum_weakened():
    cipher_prim = next(p for p in parse_cipher("ECDHE-RSA-AES128-GCM-SHA256").primitives
                       if p.role == "cipher")
    assert cipher_prim.quantum_risk == QuantumRisk.QUANTUM_WEAKENED


def test_public_key_classification():
    assert classify_public_key("RSA", 2048)[0] == QuantumRisk.QUANTUM_VULNERABLE
    assert classify_public_key("RSA", 1024)[0] == QuantumRisk.BROKEN_NOW
    assert classify_public_key("ECDSA", 256, "secp256r1")[0] == QuantumRisk.QUANTUM_VULNERABLE
    assert classify_public_key("Ed25519", 256, "ed25519")[0] == QuantumRisk.QUANTUM_VULNERABLE
    assert classify_public_key("ML-DSA-65", None)[0] == QuantumRisk.PQ_SAFE


def test_signature_classification():
    assert classify_signature("sha256WithRSAEncryption")[0] == QuantumRisk.QUANTUM_VULNERABLE
    assert classify_signature("sha1WithRSAEncryption")[0] == QuantumRisk.BROKEN_NOW
    assert classify_signature("md5WithRSAEncryption")[0] == QuantumRisk.BROKEN_NOW
    assert classify_signature("ecdsa-with-SHA384")[0] == QuantumRisk.QUANTUM_VULNERABLE


def test_protocol_classification():
    assert classify_protocol("TLSv1.0")[0] == QuantumRisk.BROKEN_NOW
    assert is_weak_protocol("TLSv1.1") is True
    assert is_weak_protocol("TLSv1.2") is False
    assert classify_protocol("TLSv1.3")[0] == QuantumRisk.QUANTUM_VULNERABLE


def test_pq_detection():
    assert is_pq_algorithm("X25519MLKEM768") is True
    assert is_pq_algorithm("x25519_kyber768") is True
    assert is_pq_algorithm("ML-DSA-87") is True
    assert is_pq_algorithm("ECDHE") is False
    assert is_pq_algorithm("RSA") is False
