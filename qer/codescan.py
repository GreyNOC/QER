"""Offline code & dependency crypto scanner (shift-left companion to the radar).

Walks a directory tree and inventories cryptography *in source*, the way the TLS
radar inventories it *on the wire* — feeding the same ``Finding`` model, quantum
classification, and SIEM feed. It looks for:

* asymmetric algorithm usage (RSA / DSA / DH / ECDSA / ECDH / Ed25519 / X25519) — quantum-vulnerable
* present-day-broken primitives (MD5, SHA-1, DES/3DES, RC4) — broken-now
* JWT / JWS signing algorithms (RS*/ES*/PS*/EdDSA, and the dangerous ``alg:none``)
* post-quantum libraries (ML-KEM/Kyber, ML-DSA/Dilithium, SLH-DSA, liboqs) — pq-safe
* hardcoded PEM private keys (a secret-in-repo finding) and certificates
* SSH keys (by type) and dependency-manifest crypto libraries

It is heuristic by nature (pattern matching over text), so it errs toward
visibility: better to surface a candidate than miss it. Findings carry a
``file:line`` location.
"""

from __future__ import annotations

import datetime as dt
import os
import re
from dataclasses import dataclass, field

from .classify import classify_public_key
from .models import Finding, QuantumRisk, Severity

try:
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.x509 import load_pem_x509_certificate
    HAVE_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover
    HAVE_CRYPTOGRAPHY = False

REF_NIST_PQC = "https://csrc.nist.gov/projects/post-quantum-cryptography"

SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "dist", "build",
             "__pycache__", ".mypy_cache", ".pytest_cache", ".tox", "target",
             ".idea", ".vscode", ".gradle", "vendor", "out", "site-packages"}
MAX_FILE_BYTES = 2_000_000
BINARY_KEY_EXTS = {".der", ".p12", ".pfx", ".jks", ".keystore"}
MANIFESTS = {"requirements.txt", "pyproject.toml", "pipfile", "package.json",
             "package-lock.json", "go.mod", "go.sum", "pom.xml", "build.gradle",
             "cargo.toml", "gemfile", "composer.json"}

# Dependency-manifest crypto libraries -> (severity, note)
CRYPTO_LIBS = {
    "pyjwt": (Severity.MEDIUM, "JWT library — commonly used with RS*/ES* (quantum-vulnerable) signatures."),
    "jsonwebtoken": (Severity.MEDIUM, "JWT library — commonly used with RS*/ES* signatures."),
    "jose": (Severity.MEDIUM, "JOSE/JWT library."),
    "rsa": (Severity.MEDIUM, "Dedicated RSA library — quantum-vulnerable by design."),
    "ecdsa": (Severity.MEDIUM, "ECDSA library — quantum-vulnerable by design."),
    "elliptic": (Severity.MEDIUM, "Elliptic-curve library — quantum-vulnerable by design."),
    "pycrypto": (Severity.HIGH, "Unmaintained crypto library; replace with 'cryptography' or pycryptodome."),
    "node-forge": (Severity.LOW, "General crypto library."),
    "cryptography": (Severity.INFO, "General crypto toolkit; inventory its algorithm usage."),
    "pycryptodome": (Severity.INFO, "General crypto toolkit."),
    "paramiko": (Severity.INFO, "SSH library."),
    "bouncycastle": (Severity.INFO, "General crypto toolkit."),
    "bcprov": (Severity.INFO, "BouncyCastle provider."),
    "openssl": (Severity.INFO, "OpenSSL bindings."),
}


@dataclass
class _Rule:
    regex: "re.Pattern"
    fid: str
    title: str
    risk: QuantumRisk
    severity: Severity
    category: str
    recommendation: str = ""


def _r(pattern: str, fid: str, title: str, risk: QuantumRisk, sev: Severity,
       cat: str, reco: str = "") -> _Rule:
    return _Rule(re.compile(pattern), fid, title, risk, sev, cat, reco)


QV = QuantumRisk.QUANTUM_VULNERABLE
BN = QuantumRisk.BROKEN_NOW
PQ = QuantumRisk.PQ_SAFE

_RULES = [
    # --- asymmetric (quantum-vulnerable) ---
    _r(r'(?i)(rsa\.generate_private_key|RSA\.generate|rsa\.GenerateKey|'
       r'getInstance\(\s*"RSA"|new RSACryptoServiceProvider|generateKeyPair\w*\(\s*["\']rsa["\']|'
       r'crypto/rsa|["\']RSA(?:-OAEP|-PSS|/ECB)?["\'])',
       "QER-CODE-RSA", "RSA usage", QV, Severity.MEDIUM, "code-asymmetric",
       "Inventory for PQC migration; plan ML-KEM (encryption) / ML-DSA (signatures)."),
    _r(r'(?i)(ecdsa|ec\.generate_private_key|crypto/ecdsa|crypto/elliptic|'
       r'getInstance\(\s*"EC"|secp256r1|secp384r1|secp521r1|prime256v1|nistp(?:256|384|521))',
       "QER-CODE-EC", "Elliptic-curve (ECDSA/ECDH) usage", QV, Severity.MEDIUM, "code-asymmetric",
       "Elliptic-curve crypto is broken by Shor; track for PQC migration."),
    _r(r'(?i)(ed25519|ed448|x25519|x448|curve25519)',
       "QER-CODE-EDDSA", "Edwards/Montgomery curve (Ed25519/X25519) usage", QV, Severity.MEDIUM,
       "code-asymmetric", "Curve25519/448 are elliptic-curve; quantum-vulnerable."),
    _r(r'(?i)(diffiehellman|dh_generate|dhparam|crypto/dh\b|getInstance\(\s*"DiffieHellman")',
       "QER-CODE-DH", "Diffie-Hellman usage", QV, Severity.MEDIUM, "code-asymmetric",
       "Finite-field DH is quantum-vulnerable."),
    _r(r'(?i)(dsa\.generate|getInstance\(\s*"DSA"|crypto/dsa)',
       "QER-CODE-DSA", "DSA usage", QV, Severity.MEDIUM, "code-asymmetric",
       "DSA is quantum-vulnerable and broadly deprecated."),
    # --- broken-now ---
    _r(r'(?i)(hashlib\.md5|\bMD5\b|getInstance\(\s*"MD5"|createHash\(\s*["\']md5["\']|md5\.new)',
       "QER-CODE-MD5", "MD5 usage", BN, Severity.HIGH, "code-weak",
       "MD5 is broken; replace with SHA-256+ for any security use."),
    _r(r'(?i)(hashlib\.sha1|\bSHA-?1\b|getInstance\(\s*"SHA-?1"|createHash\(\s*["\']sha1["\'])',
       "QER-CODE-SHA1", "SHA-1 usage", BN, Severity.MEDIUM, "code-weak",
       "SHA-1 is broken for signatures; migrate to SHA-256+."),
    _r(r'(?i)\b(3?des|desede|rc4|arcfour|blowfish)\b',
       "QER-CODE-WEAKCIPHER", "Weak/legacy cipher usage", BN, Severity.HIGH, "code-weak",
       "DES/3DES/RC4/Blowfish are obsolete; use AES-256-GCM or ChaCha20."),
    # --- JWT / JWS ---
    _r(r'(?i)("alg"\s*:\s*"|algorithm[s]?\s*[=:]\s*\[?\s*["\'])(RS|ES|PS)(256|384|512)',
       "QER-CODE-JWT-ASYM", "JWT asymmetric signing algorithm (RS/ES/PS)", QV, Severity.MEDIUM,
       "code-jwt", "RS*/ES*/PS* JWT signatures are quantum-vulnerable; track for PQC."),
    _r(r'(?i)("alg"\s*:\s*"|algorithm[s]?\s*[=:]\s*\[?\s*["\'])EdDSA',
       "QER-CODE-JWT-EDDSA", "JWT EdDSA signing algorithm", QV, Severity.MEDIUM, "code-jwt",
       "EdDSA is elliptic-curve; quantum-vulnerable."),
    _r(r'(?i)"alg"\s*:\s*"none"',
       "QER-CODE-JWT-NONE", 'JWT "alg":"none" (signature stripping risk)', BN, Severity.CRITICAL,
       "code-jwt", "Never accept alg=none; it disables signature verification."),
    # --- post-quantum (good signal) ---
    _r(r'(?i)\b(ml-?kem|kyber|ml-?dsa|dilithium|slh-?dsa|sphincs|falcon|liboqs|pqcrypto)',
       "QER-CODE-PQ", "Post-quantum algorithm/library reference", PQ, Severity.INFO, "code-pq",
       "Post-quantum primitive in use — good. Verify it is a vetted implementation."),
    # --- crypto library imports (inventory) ---
    _r(r'(?i)^\s*(?:from|import)\s+(cryptography|Crypto|nacl|paramiko|jwt|OpenSSL|ecdsa|rsa)\b',
       "QER-CODE-IMPORT", "Crypto library import", QuantumRisk.PQ_SAFE, Severity.INFO,
       "code-inventory", "Inventory only; review how the library is used."),
    _r(r'(?i)(require\(\s*["\'](crypto|jsonwebtoken|node-forge|elliptic|tweetnacl|jose)["\']|'
       r'import\s+(java\.security|javax\.crypto|org\.bouncycastle))',
       "QER-CODE-IMPORT", "Crypto library import", QuantumRisk.PQ_SAFE, Severity.INFO,
       "code-inventory", "Inventory only; review how the library is used."),
]

_PEM_BLOCK = re.compile(
    r"-----BEGIN ([A-Z0-9 ]+?)-----(.*?)-----END \1-----", re.DOTALL)
_SSH_KEY = re.compile(
    r"\b(ssh-rsa|ssh-dss|ecdsa-sha2-nistp\d+|ssh-ed25519|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp\d+@openssh\.com)\b")
_SSH_RISK = {
    "ssh-rsa": QV, "ssh-dss": BN, "ssh-ed25519": QV,
    "sk-ssh-ed25519@openssh.com": QV,
}


@dataclass
class CodeReport:
    root: str
    files_scanned: int = 0
    findings: list = field(default_factory=list)
    scanned_at: str = ""


def _finding(fid, title, sev, risk, cat, location, evidence, reco) -> Finding:
    return Finding(id=fid, title=title, severity=sev, quantum_risk=risk, category=cat,
                   host="(code)", port=0, description=title, evidence=evidence[:200],
                   recommendation=reco, location=location, references=[REF_NIST_PQC])


def _scan_source(relpath: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    seen: set[str] = set()
    lines = text.splitlines()
    for lineno, line in enumerate(lines, 1):
        for rule in _RULES:
            if rule.fid in seen:
                continue
            if rule.regex.search(line):
                seen.add(rule.fid)
                out.append(_finding(rule.fid, rule.title, rule.severity, rule.risk,
                                    rule.category, f"{relpath}:{lineno}", line.strip(),
                                    rule.recommendation))
    return out


def _scan_pem(relpath: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    for m in _PEM_BLOCK.finditer(text):
        kind = m.group(1).strip()
        lineno = text[:m.start()].count("\n") + 1
        loc = f"{relpath}:{lineno}"
        if "PRIVATE KEY" in kind:
            risk, bits, alg = QV, None, kind.replace(" PRIVATE KEY", "").strip() or "private-key"
            if HAVE_CRYPTOGRAPHY:
                try:
                    key = load_pem_private_key(m.group(0).encode(), password=None)
                    alg, bits, risk = _key_alg(key)
                except Exception:
                    pass
            out.append(_finding(
                "QER-CODE-PRIVKEY", f"Hardcoded private key in repository ({alg})",
                Severity.HIGH, risk, "secret", loc, m.group(0).splitlines()[0],
                "Remove the private key from source control, rotate it, and store it in a secret manager."))
        elif kind == "CERTIFICATE" and HAVE_CRYPTOGRAPHY:
            try:
                cert = load_pem_x509_certificate(m.group(0).encode())
                alg, bits, risk = _key_alg(cert.public_key())
                out.append(_finding(
                    "QER-CODE-CERT", f"Certificate in repository ({alg}{'-' + str(bits) if bits else ''})",
                    Severity.LOW, risk, "code-inventory", loc, str(cert.subject.rfc4514_string()),
                    "Inventory; ensure key algorithm is on the PQC migration plan."))
            except Exception:
                pass
    return out


def _scan_ssh(relpath: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    seen: set[str] = set()
    for lineno, line in enumerate(text.splitlines(), 1):
        m = _SSH_KEY.search(line)
        if not m or m.group(1) in seen:
            continue
        seen.add(m.group(1))
        ktype = m.group(1)
        risk = _SSH_RISK.get(ktype, QV)
        sev = Severity.HIGH if ktype == "ssh-dss" else Severity.MEDIUM
        out.append(_finding(
            "QER-CODE-SSHKEY", f"SSH key material ({ktype})", sev, risk, "code-asymmetric",
            f"{relpath}:{lineno}", line.strip(),
            "SSH host/user keys are quantum-vulnerable; track for PQC (e.g. sntrup761x25519)."))
    return out


def _scan_manifest(relpath: str, name: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    low = text.lower()
    seen: set[str] = set()
    for lib, (sev, note) in CRYPTO_LIBS.items():
        if lib in seen:
            continue
        if re.search(rf"(?i)(?<![\w-]){re.escape(lib)}(?![\w-])", low):
            seen.add(lib)
            risk = QV if sev in (Severity.MEDIUM,) and lib in ("rsa", "ecdsa", "elliptic") else QuantumRisk.PQ_SAFE
            out.append(_finding(
                "QER-CODE-DEP", f"Crypto dependency: {lib}", sev, risk, "code-dependency",
                relpath, f"{name} declares '{lib}'", note))
    return out


def _key_alg(key):
    if not HAVE_CRYPTOGRAPHY:
        return "unknown", None, QV
    if isinstance(key, rsa.RSAPrivateKey) or isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size, classify_public_key("RSA", key.key_size)[0]
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return "ECDSA", key.key_size, classify_public_key("ECDSA", key.key_size, key.curve.name)[0]
    if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
        return "Ed25519", 256, QV
    if isinstance(key, (ed448.Ed448PrivateKey, ed448.Ed448PublicKey)):
        return "Ed448", 448, QV
    if isinstance(key, (dsa.DSAPrivateKey, dsa.DSAPublicKey)):
        return "DSA", key.key_size, QV
    return type(key).__name__, None, QV


def _looks_binary(chunk: bytes) -> bool:
    return b"\x00" in chunk


def scan_path(root: str, max_file_bytes: int = MAX_FILE_BYTES) -> CodeReport:
    report = CodeReport(root=root, scanned_at=dt.datetime.now(dt.timezone.utc).isoformat())

    if os.path.isfile(root):
        files = [root]
        base = os.path.dirname(root) or "."
    else:
        files = []
        base = root
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                files.append(os.path.join(dirpath, fn))

    for path in files:
        try:
            if os.path.getsize(path) > max_file_bytes:
                continue
        except OSError:
            continue
        rel = os.path.relpath(path, base).replace("\\", "/")
        name = os.path.basename(path).lower()
        ext = os.path.splitext(name)[1]

        if ext in BINARY_KEY_EXTS:
            report.findings.append(_finding(
                "QER-CODE-KEYFILE", f"Binary key/cert artifact ({ext})", Severity.MEDIUM, QV,
                "secret", rel, name, "Inventory; ensure private material is not committed."))
            report.files_scanned += 1
            continue

        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError:
            continue
        if _looks_binary(raw[:1024]):
            continue
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            continue

        report.files_scanned += 1
        report.findings.extend(_scan_source(rel, text))
        if "-----BEGIN" in text:
            report.findings.extend(_scan_pem(rel, text))
        if name in ("authorized_keys", "known_hosts") or name.endswith(".pub") or "ssh-" in text[:4096]:
            report.findings.extend(_scan_ssh(rel, text))
        if name in MANIFESTS:
            report.findings.extend(_scan_manifest(rel, name, text))

    report.findings.sort(key=lambda f: (-int(f.severity), f.location))
    return report
