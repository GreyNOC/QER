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
