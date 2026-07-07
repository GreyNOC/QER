"""The cryptographic knowledge base.

This module is pure logic — no sockets, no I/O. Given the names of things the
scanner observed on the wire (a TLS version string, an OpenSSL cipher-suite
name, a certificate public-key algorithm, a signature algorithm), it returns a
``QuantumRisk`` classification and a structured CBOM entry.

The threat model it encodes:

* Shor's algorithm breaks the hardness assumptions behind RSA, finite-field DH,
  and all elliptic-curve crypto (ECDH/ECDSA/EdDSA). A future cryptographically
  relevant quantum computer (CRQC) recovers private keys from public keys, so
  *any* deployment of these is ``QUANTUM_VULNERABLE``.
* Grover's algorithm gives only a quadratic speed-up against symmetric primitives,
  so an n-bit cipher offers ~n/2-bit post-quantum security. AES-256 / ChaCha20
  stay comfortable (``PQ_SAFE``); AES-128 drops to 64-bit (``QUANTUM_WEAKENED``).
* Some things are simply broken today (RC4, DES/3DES, MD5, SHA-1 signatures,
  TLS <= 1.1, RSA keys < 2048). Those are ``BROKEN_NOW`` and outrank quantum
  concerns.
* Post-quantum and hybrid constructions (ML-KEM/Kyber, ML-DSA/Dilithium,
  SLH-DSA/SPHINCS+, FN-DSA/Falcon, and X25519MLKEM768-style hybrids) are
  ``PQ_SAFE``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .models import CryptoPrimitive, QuantumRisk, Severity

# NIST reference for the migration program.
NIST_PQC = "https://csrc.nist.gov/projects/post-quantum-cryptography"
NIST_SP1800_38 = "https://www.nccoe.nist.gov/crypto-agility-considerations-migrating-post-quantum-cryptographic-algorithms"

# --------------------------------------------------------------------------- #
# Post-quantum / hybrid recognition
# --------------------------------------------------------------------------- #

# Substrings that, if present in a key-exchange group or algorithm name, mark it
# as post-quantum or hybrid (and therefore PQ-safe).
_PQ_TOKENS = (
    "mlkem", "ml-kem", "kyber",          # KEMs (FIPS 203 / round-3 Kyber)
    "mldsa", "ml-dsa", "dilithium",      # signatures (FIPS 204)
    "slhdsa", "slh-dsa", "sphincs",      # hash-based signatures (FIPS 205)
    "fndsa", "fn-dsa", "falcon",         # signatures (FIPS 206, draft)
    "xmss", "hss-lms", "lms",            # stateful hash-based signatures (NIST SP 800-208)
    "frodo", "bike", "hqc", "mceliece",  # alt KEMs
    "sntrup", "ntruprime", "ntrulpr",    # (Streamlined) NTRU Prime (OpenSSH SSH KEX)
)

# Named hybrid groups worth recognising explicitly (TLS key_share groups).
HYBRID_GROUPS = {
    "x25519mlkem768",
    "x25519kyber768draft00",
    "secp256r1mlkem768",
    "secp384r1mlkem1024",
    "p256_kyber768",
    "p384_kyber1024",
}


def normalize(name: Optional[str]) -> str:
    return (name or "").strip().lower().replace("_", "").replace("-", "").replace(" ", "")


def is_pq_algorithm(name: Optional[str]) -> bool:
    """True if the algorithm/group name denotes a post-quantum or hybrid scheme."""
    n = (name or "").lower()
    if normalize(name) in HYBRID_GROUPS:
        return True
    return any(tok.replace("-", "") in normalize(name) or tok in n for tok in _PQ_TOKENS)


# --------------------------------------------------------------------------- #
# TLS protocol versions
# --------------------------------------------------------------------------- #

# version string (as Python/OpenSSL reports it) -> (risk, severity, note)
_PROTOCOL_TABLE = {
    "SSLv2": (QuantumRisk.BROKEN_NOW, Severity.CRITICAL, "SSL 2.0 is catastrophically broken and long removed from libraries."),
    "SSLv3": (QuantumRisk.BROKEN_NOW, Severity.CRITICAL, "SSL 3.0 is broken (POODLE); disable immediately."),
    "TLSv1": (QuantumRisk.BROKEN_NOW, Severity.HIGH, "TLS 1.0 is deprecated (RFC 8996); disable."),
    "TLSv1.0": (QuantumRisk.BROKEN_NOW, Severity.HIGH, "TLS 1.0 is deprecated (RFC 8996); disable."),
    "TLSv1.1": (QuantumRisk.BROKEN_NOW, Severity.HIGH, "TLS 1.1 is deprecated (RFC 8996); disable."),
    "TLSv1.2": (QuantumRisk.QUANTUM_VULNERABLE, Severity.MEDIUM, "TLS 1.2 is acceptable but its key exchange is classical; plan hybrid PQ."),
    "TLSv1.3": (QuantumRisk.QUANTUM_VULNERABLE, Severity.LOW, "TLS 1.3 is modern; key exchange is still classical unless a hybrid PQ group is negotiated."),
}


def classify_protocol(version: str) -> tuple[QuantumRisk, Severity, str]:
    return _PROTOCOL_TABLE.get(
        version,
        (QuantumRisk.QUANTUM_VULNERABLE, Severity.LOW, "Unrecognised protocol version."),
    )


def is_weak_protocol(version: str) -> bool:
    risk, _, _ = classify_protocol(version)
    return risk == QuantumRisk.BROKEN_NOW


# --------------------------------------------------------------------------- #
# Cipher-suite parsing
# --------------------------------------------------------------------------- #

_FS_KEX = {"ECDHE", "DHE", "EECDH", "EDH"}      # ephemeral -> forward secret (classically)
_STATIC_KEX = {"ECDH", "DH", "RSA"}             # static / key transport -> no forward secrecy


@dataclass
class CipherProfile:
    name: str
    key_exchange: str
    authentication: str
    cipher: str
    cipher_bits: Optional[int]
    mode: str
    mac: str
    forward_secret: bool
    quantum_risk: QuantumRisk          # worst component, the suite's dominating risk
    primitives: list                   # list[CryptoPrimitive]
    notes: list                        # list[str]


def _detect_kex_auth(name_u: str, is_tls13: bool) -> tuple[str, str]:
    """Return (key_exchange, authentication) from an upper-cased suite name."""
    if is_tls13:
        # TLS 1.3 suite names carry no KEX/Auth token; key exchange is always an
        # ephemeral (EC)DHE group chosen via key_share, auth comes from the cert.
        return "ECDHE", "cert"

    kex = "RSA"   # default: classic RSA key transport (no FS) when no prefix present
    auth = "RSA"
    if name_u.startswith("AECDH"):
        kex = "ECDHE"                 # anonymous ephemeral ECDH — still forward-secret
    elif name_u.startswith("ADH"):
        kex = "DHE"                   # anonymous ephemeral DH — still forward-secret
    elif name_u.startswith("ECDHE") or name_u.startswith("EECDH"):
        kex = "ECDHE"
    elif name_u.startswith("DHE") or name_u.startswith("EDH"):
        kex = "DHE"
    elif name_u.startswith("ECDH"):
        kex = "ECDH"
    elif name_u.startswith("DH"):
        kex = "DH"
    elif name_u.startswith("PSK") or "PSK" in name_u.split("-")[0]:
        kex = "PSK"

    if "ECDSA" in name_u:
        auth = "ECDSA"
    elif "RSA" in name_u:
        auth = "RSA"
    elif "DSS" in name_u or "DSA" in name_u:
        auth = "DSA"
    elif "PSK" in name_u:
        auth = "PSK"
    elif "ANON" in name_u or name_u.startswith("ADH") or name_u.startswith("AECDH"):
        auth = "anon"
    return kex, auth


def _detect_cipher(name_u: str) -> tuple[str, Optional[int], str, QuantumRisk, str]:
    """Return (cipher, bits, mode, risk, note) for the bulk cipher."""
    mode = "GCM" if "GCM" in name_u else \
           "CCM" if "CCM" in name_u else \
           "POLY1305" if "POLY1305" in name_u or "CHACHA20" in name_u else \
           "CBC"
    if "CHACHA20" in name_u:
        return "ChaCha20-Poly1305", 256, "POLY1305", QuantumRisk.PQ_SAFE, ""
    if "AES256" in name_u or "AES-256" in name_u or "AES_256" in name_u:
        return "AES-256", 256, mode, QuantumRisk.PQ_SAFE, ""
    if "AES128" in name_u or "AES-128" in name_u or "AES_128" in name_u:
        return "AES-128", 128, mode, QuantumRisk.QUANTUM_WEAKENED, \
            "AES-128 offers only ~64-bit security against Grover; prefer AES-256 for long-lived data."
    if "CAMELLIA256" in name_u:
        return "Camellia-256", 256, mode, QuantumRisk.PQ_SAFE, ""
    if "CAMELLIA128" in name_u:
        return "Camellia-128", 128, mode, QuantumRisk.QUANTUM_WEAKENED, "128-bit symmetric; weak post-Grover margin."
    if "3DES" in name_u or "DES-CBC3" in name_u or "DESCBC3" in name_u:
        return "3DES", 112, "CBC", QuantumRisk.BROKEN_NOW, "3DES is deprecated (SWEET32); remove."
    if "RC4" in name_u:
        return "RC4", None, "stream", QuantumRisk.BROKEN_NOW, "RC4 is broken; remove."
    if "DES" in name_u:
        return "DES", 56, "CBC", QuantumRisk.BROKEN_NOW, "Single DES is broken; remove."
    if "NULL" in name_u:
        return "NULL", 0, "none", QuantumRisk.BROKEN_NOW, "NULL cipher provides no confidentiality."
    if "SEED" in name_u:
        return "SEED", 128, mode, QuantumRisk.QUANTUM_WEAKENED, "Legacy 128-bit cipher."
    if "IDEA" in name_u:
        return "IDEA", 128, "CBC", QuantumRisk.QUANTUM_WEAKENED, "Legacy 128-bit cipher."
    return "unknown", None, mode, QuantumRisk.QUANTUM_WEAKENED, "Unrecognised bulk cipher."


def _detect_mac(name_u: str, mode: str) -> tuple[str, QuantumRisk, str]:
    if mode in ("GCM", "CCM", "POLY1305"):
        return "AEAD", QuantumRisk.PQ_SAFE, ""
    if name_u.endswith("MD5") or "-MD5" in name_u:
        return "MD5", QuantumRisk.BROKEN_NOW, "HMAC-MD5 is obsolete."
    if name_u.endswith("SHA384") or "SHA384" in name_u:
        return "SHA-384", QuantumRisk.PQ_SAFE, ""
    if name_u.endswith("SHA256") or "SHA256" in name_u:
        return "SHA-256", QuantumRisk.PQ_SAFE, ""
    if name_u.endswith("SHA") or "-SHA" in name_u:
        # bare "SHA" in a suite name is SHA-1
        return "SHA-1", QuantumRisk.BROKEN_NOW, "SHA-1 MAC is legacy; CBC+SHA-1 suites should be retired."
    return "unknown", QuantumRisk.QUANTUM_WEAKENED, ""


def parse_cipher(openssl_name: Optional[str]) -> Optional[CipherProfile]:
    """Parse an OpenSSL-style suite name (what ``ssl.SSLSocket.cipher()`` returns)
    such as ``ECDHE-RSA-AES256-GCM-SHA384`` or a TLS 1.3 IANA name such as
    ``TLS_AES_128_GCM_SHA256`` into a structured, classified profile."""
    if not openssl_name:
        return None
    raw = openssl_name.strip()
    name_u = raw.upper()
    is_tls13 = name_u.startswith("TLS_") or name_u.startswith("TLS13")

    kex, auth = _detect_kex_auth(name_u, is_tls13)
    cipher, cbits, mode, cipher_risk, cipher_note = _detect_cipher(name_u)
    mac, mac_risk, mac_note = _detect_mac(name_u, mode)

    forward_secret = is_tls13 or kex in _FS_KEX

    notes: list[str] = []
    primitives: list[CryptoPrimitive] = []

    # Key exchange — the HNDL-critical component.
    if kex in ("ECDHE", "ECDH"):
        kex_risk = QuantumRisk.QUANTUM_VULNERABLE
        kex_note = "Elliptic-curve key exchange is broken by Shor; recorded handshakes are HNDL-exposed."
    elif kex in ("DHE", "DH"):
        kex_risk = QuantumRisk.QUANTUM_VULNERABLE
        kex_note = "Finite-field DH key exchange is broken by Shor; HNDL-exposed."
    elif kex == "RSA":
        kex_risk = QuantumRisk.QUANTUM_VULNERABLE
        kex_note = "RSA key transport: no forward secrecy AND quantum-vulnerable — worst case for HNDL."
        notes.append("No forward secrecy: a single key compromise (classical or quantum) exposes all sessions.")
    elif kex == "PSK":
        kex_risk = QuantumRisk.PQ_SAFE
        kex_note = "Pre-shared-key exchange (symmetric); not Shor-vulnerable, but key distribution is out of band."
    else:
        kex_risk = QuantumRisk.QUANTUM_VULNERABLE
        kex_note = ""
    if is_pq_algorithm(kex):
        kex_risk = QuantumRisk.PQ_SAFE
        kex_note = "Post-quantum / hybrid key exchange."

    primitives.append(CryptoPrimitive(
        role="key-exchange", algorithm=kex, quantum_risk=kex_risk,
        forward_secret=forward_secret, note=kex_note,
    ))
    if auth not in ("cert", "anon", "PSK"):
        auth_risk = QuantumRisk.PQ_SAFE if is_pq_algorithm(auth) else QuantumRisk.QUANTUM_VULNERABLE
        primitives.append(CryptoPrimitive(
            role="authentication", algorithm=auth, quantum_risk=auth_risk,
            note="Signature authentication is quantum-vulnerable (Shor) — affects future impersonation, not past traffic."
            if auth_risk == QuantumRisk.QUANTUM_VULNERABLE else "",
        ))
    primitives.append(CryptoPrimitive(
        role="cipher", algorithm=cipher, quantum_risk=cipher_risk, bits=cbits, detail=mode, note=cipher_note,
    ))
    primitives.append(CryptoPrimitive(role="mac", algorithm=mac, quantum_risk=mac_risk, note=mac_note))

    for n in (kex_note and "" or None, cipher_note, mac_note):
        if n:
            notes.append(n)

    suite_risk = max(p.quantum_risk for p in primitives)

    return CipherProfile(
        name=raw, key_exchange=kex, authentication=auth, cipher=cipher,
        cipher_bits=cbits, mode=mode, mac=mac, forward_secret=forward_secret,
        quantum_risk=suite_risk, primitives=primitives, notes=notes,
    )


# --------------------------------------------------------------------------- #
# Certificate public keys & signatures
# --------------------------------------------------------------------------- #

def classify_public_key(algorithm: str, bits: Optional[int], curve: Optional[str] = None
                        ) -> tuple[QuantumRisk, Severity, str]:
    a = (algorithm or "").upper()
    if is_pq_algorithm(algorithm) or is_pq_algorithm(curve):
        return QuantumRisk.PQ_SAFE, Severity.INFO, "Post-quantum public key."
    if a.startswith("RSA"):
        if bits and bits < 2048:
            return QuantumRisk.BROKEN_NOW, Severity.HIGH, f"RSA-{bits} is below the 2048-bit floor; weak even classically."
        return QuantumRisk.QUANTUM_VULNERABLE, Severity.HIGH, f"RSA public key is broken by Shor's algorithm."
    if a in ("EC", "ECDSA", "ECDH") or "EC" in a:
        return QuantumRisk.QUANTUM_VULNERABLE, Severity.HIGH, "Elliptic-curve public key is broken by Shor's algorithm."
    if a.startswith("ED"):  # Ed25519 / Ed448
        return QuantumRisk.QUANTUM_VULNERABLE, Severity.HIGH, "EdDSA is elliptic-curve based; broken by Shor's algorithm."
    if a.startswith("DSA"):
        return QuantumRisk.QUANTUM_VULNERABLE, Severity.HIGH, "DSA is quantum-vulnerable and broadly deprecated."
    return QuantumRisk.QUANTUM_VULNERABLE, Severity.MEDIUM, "Unrecognised public-key algorithm; treated as quantum-vulnerable."


# common signature-algorithm OID names -> (hash, family)
def classify_signature(sig_alg_name: str) -> tuple[QuantumRisk, Severity, Optional[str], str]:
    """Classify a certificate signature algorithm such as
    ``sha256WithRSAEncryption`` or ``ecdsa-with-SHA256``.

    Returns (risk, severity, hash_name, note). The result is the worst of the
    hash strength and the signature family's quantum risk."""
    s = (sig_alg_name or "").lower()
    if is_pq_algorithm(sig_alg_name):
        return QuantumRisk.PQ_SAFE, Severity.INFO, None, "Post-quantum signature."

    # Hash component. SHAKE128/256 (RFC 8692) are SHA-3 XOFs and sound, so they
    # must be excluded from the SHA-1 catch-all below (both contain "sha").
    if "md5" in s or "md2" in s or "md4" in s:
        broken_md = "md5" if "md5" in s else ("md2" if "md2" in s else "md4")
        hash_name, hash_risk, hash_sev = broken_md, QuantumRisk.BROKEN_NOW, Severity.CRITICAL
    elif "shake" in s:
        hash_name, hash_risk, hash_sev = "shake", QuantumRisk.PQ_SAFE, Severity.INFO
    elif "sha1" in s or "sha-1" in s or ("sha" in s and "sha2" not in s and "sha256" not in s
                                         and "sha384" not in s and "sha512" not in s and "sha3" not in s):
        hash_name, hash_risk, hash_sev = "sha1", QuantumRisk.BROKEN_NOW, Severity.HIGH
    elif "sha512" in s:
        hash_name, hash_risk, hash_sev = "sha512", QuantumRisk.PQ_SAFE, Severity.INFO
    elif "sha384" in s:
        hash_name, hash_risk, hash_sev = "sha384", QuantumRisk.PQ_SAFE, Severity.INFO
    elif "sha256" in s:
        hash_name, hash_risk, hash_sev = "sha256", QuantumRisk.PQ_SAFE, Severity.INFO
    else:
        hash_name, hash_risk, hash_sev = None, QuantumRisk.PQ_SAFE, Severity.INFO

    # Signature family
    if "ecdsa" in s or "ec" in s:
        fam_risk = QuantumRisk.QUANTUM_VULNERABLE
    elif "rsa" in s:
        fam_risk = QuantumRisk.QUANTUM_VULNERABLE
    elif "dsa" in s:
        fam_risk = QuantumRisk.QUANTUM_VULNERABLE
    elif "ed25519" in s or "ed448" in s:
        fam_risk = QuantumRisk.QUANTUM_VULNERABLE
    else:
        fam_risk = QuantumRisk.QUANTUM_VULNERABLE

    risk = max(hash_risk, fam_risk)
    sev = hash_sev if hash_risk >= fam_risk else Severity.HIGH
    if hash_name in ("md5", "sha1"):
        note = f"Signature hash {hash_name} is broken; certificate should be reissued."
    else:
        note = "Signature scheme is quantum-vulnerable (Shor) but hash is sound."
    return risk, sev, hash_name, note
