"""CycloneDX 1.6 cryptographic bill of materials (CBOM) exporter.

This is QER's thesis rendered in the industry-standard format. CycloneDX 1.6
added first-class *cryptographic assets* (OWASP), so a scan's findings become a
portable, tool-interoperable CBOM: every TLS protocol, certificate, and
algorithm QER observed is emitted as a ``cryptographic-asset`` component, with
NIST quantum-security levels and a ``qer:quantumRisk`` property, and certificates
reference the algorithm components for their signature and public key.

Reference: https://cyclonedx.org/docs/1.6/json/#components_items_cryptoProperties
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Optional

from .. import __version__
from ..classify import is_pq_algorithm
from ..models import EndpointReport, QuantumRisk

# QuantumRisk -> NIST PQC security level (coarse: 0 means no quantum resistance).
_NIST_LEVEL = {
    QuantumRisk.PQ_SAFE: 3,
    QuantumRisk.QUANTUM_WEAKENED: 1,
    QuantumRisk.QUANTUM_VULNERABLE: 0,
    QuantumRisk.BROKEN_NOW: 0,
}


def _slug(name: str) -> str:
    return "".join(ch if ch.isalnum() else "-" for ch in (name or "unknown")).strip("-").lower() or "unknown"


def _primitive(role: str, name: str) -> str:
    """Map a QER primitive role/name to a CycloneDX algorithm primitive."""
    n = (name or "").upper()
    if role == "key-exchange":
        return "kem" if is_pq_algorithm(name) else "key-agree"
    if role == "authentication":
        return "signature"
    if role == "certificate-key":
        return "pke" if n.startswith("RSA") else "signature"
    if role == "cipher":
        if "POLY1305" in n:
            return "ae"
        if "CHACHA" in n:
            return "stream-cipher"
        return "block-cipher"
    if role == "mac":
        return "mac"
    return "other"


def _tls_version(version: Optional[str]) -> str:
    return {
        "TLSv1.3": "1.3", "TLSv1.2": "1.2", "TLSv1.1": "1.1",
        "TLSv1.0": "1.0", "TLSv1": "1.0", "SSLv3": "3.0",
    }.get(version or "", version or "")


def _prune(obj):
    """Drop None values (CycloneDX validators reject explicit nulls)."""
    if isinstance(obj, dict):
        return {k: _prune(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_prune(v) for v in obj]
    return obj


def _serial_number(reports: list[EndpointReport]) -> str:
    """Deterministic but RFC-4122-valid serial. Building a UUID from hash bytes
    with version=4 forces the version/variant bits the CycloneDX 1.6 schema
    requires (raw hash slices fail its strict UUID pattern ~92% of the time)."""
    key = ",".join(sorted(f"{r.scan.host}:{r.scan.port}" for r in reports)) or "empty"
    digest = hashlib.sha256(key.encode()).digest()
    return f"urn:uuid:{uuid.UUID(bytes=digest[:16], version=4)}"


def to_cyclonedx(reports: list[EndpointReport], meta: Optional[dict] = None) -> str:
    meta = meta or {}
    algorithms: dict[str, dict] = {}        # bom-ref -> component (deduped)
    other_components: list[dict] = []

    def algo_ref(name: str, role: str, risk: QuantumRisk) -> str:
        ref = f"crypto/algorithm/{_slug(name)}"
        if ref not in algorithms:
            algorithms[ref] = {
                "type": "cryptographic-asset",
                "bom-ref": ref,
                "name": name,
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": _primitive(role, name),
                        "executionEnvironment": "software-plain-ram",
                        "nistQuantumSecurityLevel": _NIST_LEVEL.get(risk, 0),
                    },
                },
                "properties": [{"name": "qer:quantumRisk", "value": risk.label}],
            }
        return ref

    for r in reports:
        scan = r.scan
        if not scan.reachable:
            continue
        host = f"{scan.host}:{scan.port}"

        if scan.negotiated_version:
            other_components.append({
                "type": "cryptographic-asset",
                "bom-ref": f"crypto/protocol/{host}",
                "name": f"{scan.negotiated_version} ({host})",
                "cryptoProperties": {
                    "assetType": "protocol",
                    "protocolProperties": {
                        "type": "tls",
                        "version": _tls_version(scan.negotiated_version),
                        "cipherSuites": ([{"name": scan.negotiated_cipher}]
                                         if scan.negotiated_cipher else None),
                    },
                },
                "properties": [
                    {"name": "qer:host", "value": host},
                    {"name": "qer:forwardSecret", "value": str(scan.forward_secret)},
                    {"name": "qer:pqSupported", "value": str(bool(scan.pq_groups_supported))},
                    {"name": "qer:pqEnforced", "value": str(scan.pq_preferred)},
                ],
            })

        for p in scan.primitives:
            if p.role != "protocol":
                algo_ref(p.algorithm, p.role, p.quantum_risk)

        for idx, c in enumerate(scan.certificates):
            sig_ref = algo_ref(c.signature_algorithm, "authentication", c.quantum_risk)
            key_name = (f"{c.public_key_algorithm}-{c.public_key_bits}"
                        if c.public_key_bits else c.public_key_algorithm)
            key_ref = algo_ref(key_name, "certificate-key", c.quantum_risk)
            other_components.append({
                "type": "cryptographic-asset",
                "bom-ref": f"crypto/certificate/{host}/{idx}",
                "name": c.subject,
                "cryptoProperties": {
                    "assetType": "certificate",
                    "certificateProperties": {
                        "subjectName": c.subject,
                        "issuerName": c.issuer,
                        "notValidBefore": c.not_before,
                        "notValidAfter": c.not_after,
                        "certificateFormat": "X.509",
                        "signatureAlgorithmRef": sig_ref,
                        "subjectPublicKeyRef": key_ref,
                    },
                },
                "properties": [
                    {"name": "qer:host", "value": host},
                    {"name": "qer:chainPosition", "value": c.position},
                    {"name": "qer:quantumRisk", "value": c.quantum_risk.label},
                ],
            })

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": _serial_number(reports),
        "version": 1,
        "metadata": {
            "timestamp": meta.get("generated_at"),
            "tools": {"components": [{
                "type": "application", "author": "GreyNOC",
                "name": "QER", "version": meta.get("tool_version", __version__),
            }]},
            "component": {
                "type": "application",
                "bom-ref": "qer-cbom-root",
                "name": "GreyNOC Quantum Exposure Radar — cryptographic bill of materials",
            },
        },
        "components": list(algorithms.values()) + other_components,
    }
    return json.dumps(_prune(bom), indent=2)


# --------------------------------------------------------------------------- #
# Code-scan CBOM: map qer.codescan findings to crypto-asset / library components
# --------------------------------------------------------------------------- #

# finding id -> (algorithm name, CycloneDX primitive)
_CODE_ALGO = {
    "QER-CODE-RSA": ("RSA", "pke"),
    "QER-CODE-EC": ("ECDSA/ECDH", "signature"),
    "QER-CODE-EDDSA": ("Ed25519/X25519", "signature"),
    "QER-CODE-DH": ("Diffie-Hellman", "key-agree"),
    "QER-CODE-DSA": ("DSA", "signature"),
    "QER-CODE-MD5": ("MD5", "hash"),
    "QER-CODE-SHA1": ("SHA-1", "hash"),
    "QER-CODE-WEAKCIPHER": ("DES/3DES/RC4", "block-cipher"),
    "QER-CODE-JWT-ASYM": ("JWT RS/ES/PS", "signature"),
    "QER-CODE-JWT-EDDSA": ("JWT EdDSA", "signature"),
    "QER-CODE-JWT-NONE": ("JWT alg=none", "signature"),
    "QER-CODE-SAML-SIG": ("XML-DSig RSA/ECDSA/DSA", "signature"),
    "QER-CODE-SAML-WEAK": ("XML-DSig SHA-1/MD5", "signature"),
    "QER-CODE-PQ": ("post-quantum", "kem"),
}
_CODE_MATERIAL = {
    "QER-CODE-PRIVKEY": "private-key", "QER-CODE-KEYFILE": "private-key",
    "QER-CODE-SSHKEY": "private-key", "QER-CODE-CERT": "certificate",
}


def code_to_cyclonedx(report, meta: Optional[dict] = None) -> str:
    """A CycloneDX 1.6 CBOM from a qer.codescan CodeReport: algorithm crypto-assets
    (deduped, with file:line occurrences), crypto-dependency libraries, and
    key/certificate material assets."""
    meta = meta or {}
    algos: dict = {}        # name -> {"primitive","risk","locs"}
    libs: dict = {}         # lib -> {"risk","locs"}
    components: list[dict] = []
    material_i = 0          # monotonic index keeps material bom-refs unique

    for f in report.findings:
        if f.id in _CODE_ALGO:
            name, prim = _CODE_ALGO[f.id]
            e = algos.setdefault(name, {"primitive": prim, "risk": f.quantum_risk, "locs": []})
            e["risk"] = max(e["risk"], f.quantum_risk)
            e["locs"].append(f.location)
        elif f.id == "QER-CODE-DEP":
            lib = f.title.replace("Crypto dependency: ", "").strip()
            libs.setdefault(lib, {"risk": f.quantum_risk, "locs": []})["locs"].append(f.location)
        elif f.id in _CODE_MATERIAL:
            asset = _CODE_MATERIAL[f.id]
            crypto = ({"assetType": "certificate", "certificateProperties": {"certificateFormat": "X.509"}}
                      if asset == "certificate"
                      else {"assetType": "related-crypto-material",
                            "relatedCryptoMaterialProperties": {"type": "private-key"}})
            components.append({
                "type": "cryptographic-asset",
                "bom-ref": f"crypto/material/{_slug(f.id)}/{material_i}",
                "name": f.title,
                "cryptoProperties": crypto,
                "evidence": {"occurrences": [{"location": f.location}]},
                "properties": [{"name": "qer:quantumRisk", "value": f.quantum_risk.label}],
            })
            material_i += 1

    for name, e in algos.items():
        components.append({
            "type": "cryptographic-asset",
            "bom-ref": f"crypto/algorithm/{_slug(name)}",
            "name": name,
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": e["primitive"],
                    "executionEnvironment": "software-plain-ram",
                    "nistQuantumSecurityLevel": _NIST_LEVEL.get(e["risk"], 0),
                },
            },
            "evidence": {"occurrences": [{"location": loc} for loc in e["locs"][:25]]},
            "properties": [
                {"name": "qer:quantumRisk", "value": e["risk"].label},
                {"name": "qer:occurrences", "value": str(len(e["locs"]))},
            ],
        })
    for lib, e in libs.items():
        components.append({
            "type": "library",
            "bom-ref": f"library/{_slug(lib)}",
            "name": lib,
            "evidence": {"occurrences": [{"location": loc} for loc in e["locs"][:25]]},
            "properties": [
                {"name": "qer:cryptoDependency", "value": "true"},
                {"name": "qer:quantumRisk", "value": e["risk"].label},
            ],
        })

    h = hashlib.sha256((report.root or "code").encode()).hexdigest()
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.UUID(bytes=bytes.fromhex(h)[:16], version=4)}",
        "version": 1,
        "metadata": {
            "timestamp": meta.get("generated_at"),
            "tools": {"components": [{
                "type": "application", "author": "GreyNOC",
                "name": "QER", "version": meta.get("tool_version", __version__),
            }]},
            "component": {"type": "application", "bom-ref": "qer-code-cbom-root",
                          "name": f"QER code CBOM — {report.root}"},
        },
        "components": components,
    }
    return json.dumps(_prune(bom), indent=2)
