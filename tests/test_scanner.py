"""Coverage for scanner.py's pure certificate-parsing path (no network)."""

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from qer import scanner


def _self_signed_der(key, sig_hash=hashes.SHA256(), cn="qa.example.com"):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, sig_hash))
    return cert.public_bytes(serialization.Encoding.DER)


def test_parse_certificate_ecdsa():
    der = _self_signed_der(ec.generate_private_key(ec.SECP256R1()))
    ci = scanner._parse_certificate(der)
    assert ci.public_key_algorithm == "ECDSA" and ci.public_key_bits == 256
    assert ci.public_key_curve == "secp256r1"
    assert ci.is_self_signed is True and ci.is_ca is False
    assert "qa.example.com" in ci.sans
    assert ci.signature_hash == "sha256"
    assert ci.quantum_risk.label == "quantum-vulnerable"
    assert ci.days_to_expiry is not None


def test_parse_certificate_rsa():
    der = _self_signed_der(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    ci = scanner._parse_certificate(der)
    assert ci.public_key_algorithm == "RSA" and ci.public_key_bits == 2048
    assert ci.quantum_risk.label == "quantum-vulnerable"


def test_parse_chain_positions_from_real_ders():
    leaf = _self_signed_der(ec.generate_private_key(ec.SECP256R1()), cn="leaf.example.com")
    inter = _self_signed_der(ec.generate_private_key(ec.SECP256R1()), cn="ca.example.com")
    chain = scanner._parse_chain([leaf, inter])
    assert [c.position for c in chain] == ["leaf", "root"]   # both self-signed -> 2nd is "root"


def test_certinfo_from_stdlib_fallback():
    d = {
        "subject": ((("commonName", "x.example.com"),),),
        "issuer": ((("commonName", "Issuer CA"),),),
        "serialNumber": "0A1B",
        "notAfter": "Aug  1 00:00:00 2030 GMT",
        "subjectAltName": (("DNS", "x.example.com"), ("DNS", "www.x.example.com")),
    }
    ci = scanner._certinfo_from_stdlib(d)
    assert ci.quantum_risk.label == "quantum-vulnerable"        # conservative fallback
    assert "x.example.com" in ci.sans and "www.x.example.com" in ci.sans
    assert scanner._certinfo_from_stdlib({}) is None
