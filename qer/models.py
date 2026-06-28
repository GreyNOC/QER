"""Core data model for QER.

Everything the scanner observes and everything the scoring engine derives is
expressed with the dataclasses below. ``to_serializable`` turns any of them
(recursively) into JSON-friendly primitives, which is what every SIEM exporter
and the JSON report build on.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional


class QuantumRisk(IntEnum):
    """How a primitive fares against a cryptographically relevant quantum
    computer (CRQC) and/or today's classical attackers.

    Ordering matters: higher means worse, so ``max(...)`` over a set of
    primitives yields the dominating risk for an endpoint.
    """

    PQ_SAFE = 0            # Post-quantum, or symmetric/hash with >=128-bit post-Grover margin
    QUANTUM_WEAKENED = 1   # Symmetric strength halved by Grover but usable (AES-128 -> 64-bit)
    QUANTUM_VULNERABLE = 2 # Broken by Shor (RSA/DSA/DH/ECC) — the HNDL-relevant class
    BROKEN_NOW = 3         # Already weak/deprecated regardless of quantum (RC4, 3DES, SHA-1, TLS<=1.1)

    @property
    def label(self) -> str:
        return {
            QuantumRisk.PQ_SAFE: "pq-safe",
            QuantumRisk.QUANTUM_WEAKENED: "quantum-weakened",
            QuantumRisk.QUANTUM_VULNERABLE: "quantum-vulnerable",
            QuantumRisk.BROKEN_NOW: "broken-now",
        }[self]

    @classmethod
    def from_label(cls, value) -> "QuantumRisk":
        if isinstance(value, QuantumRisk):
            return value
        if isinstance(value, int):
            return cls(value)
        for m in cls:
            if m.label == value:
                return m
        return cls.PQ_SAFE


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def from_label(cls, value) -> "Severity":
        if isinstance(value, Severity):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls.__members__.get(str(value).strip().upper(), cls.INFO)


class Exposure(IntEnum):
    """Network reachability of the asset — a multiplier on urgency."""

    INTERNAL = 1
    PARTNER = 2
    EXTERNAL = 3

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: Any) -> "Exposure":
        if isinstance(value, Exposure):
            return value
        if isinstance(value, int):
            return cls(value)
        key = str(value).strip().upper()
        return cls.__members__.get(key, cls.EXTERNAL)


@dataclass
class CryptoPrimitive:
    """A single observed cryptographic primitive within an endpoint. The CBOM
    for an endpoint is just its list of these."""

    role: str                                    # key-exchange | authentication | certificate-key | signature | cipher | mac | protocol
    algorithm: str                               # canonical-ish name, e.g. "ECDHE", "RSA-2048", "AES-128-GCM"
    quantum_risk: QuantumRisk = QuantumRisk.PQ_SAFE
    detail: str = ""                             # free text, e.g. "secp256r1", "sha256WithRSAEncryption"
    bits: Optional[int] = None
    forward_secret: Optional[bool] = None
    note: str = ""


@dataclass
class CertInfo:
    subject: str
    issuer: str
    serial: str
    public_key_algorithm: str
    signature_algorithm: str
    position: str = "leaf"               # leaf | intermediate | root (within the presented chain)
    is_ca: bool = False
    is_self_signed: bool = False
    not_before: Optional[str] = None             # ISO 8601
    not_after: Optional[str] = None
    days_to_expiry: Optional[int] = None
    public_key_bits: Optional[int] = None
    public_key_curve: Optional[str] = None
    signature_hash: Optional[str] = None
    sans: list[str] = field(default_factory=list)
    quantum_risk: QuantumRisk = QuantumRisk.PQ_SAFE


@dataclass
class ScanResult:
    """Raw, factual observation of one endpoint. No business judgement here —
    just what was actually negotiated on the wire."""

    host: str
    port: int
    reachable: bool = False
    error: Optional[str] = None
    ip: Optional[str] = None
    negotiated_version: Optional[str] = None
    negotiated_cipher: Optional[str] = None
    supported_versions: list[str] = field(default_factory=list)
    weak_versions: list[str] = field(default_factory=list)
    key_exchange: Optional[str] = None
    authentication: Optional[str] = None
    forward_secret: Optional[bool] = None
    primitives: list[CryptoPrimitive] = field(default_factory=list)
    certificates: list[CertInfo] = field(default_factory=list)
    # PQ key exchange, established by the active raw-TLS probe (qer.pqprobe):
    #   pq_testable        — the probe ran
    #   pq_kex_negotiated  — server supports (and would negotiate) a PQ/hybrid group
    #   pq_groups_supported— the specific hybrid groups proven supported
    #   pq_preferred       — server *enforces* PQ (HRR-upgrades clients) vs merely
    #                        tolerates it (accepts classical when offered); None=untested
    pq_kex_negotiated: Optional[bool] = None
    pq_testable: bool = False
    pq_groups_supported: list[str] = field(default_factory=list)
    pq_preferred: Optional[bool] = None
    openssl_version: str = ""
    scanned_at: Optional[str] = None

    def dominant_risk(self) -> QuantumRisk:
        risks = [p.quantum_risk for p in self.primitives]
        risks += [c.quantum_risk for c in self.certificates]
        return max(risks) if risks else QuantumRisk.PQ_SAFE


@dataclass
class AssetProfile:
    """Business context the scanner cannot see. Supplied by the operator (via
    the targets file) and combined with scan facts to produce scores."""

    host: str
    port: int = 443
    label: str = ""
    sensitivity: int = 3            # 1..5  — how damaging is disclosure of this data
    shelf_life_years: int = 5       # how long the data must remain confidential (drives HNDL)
    exposure: Exposure = Exposure.EXTERNAL
    crypto_agility: int = 3         # 1..5  — 5 = trivially swappable, 1 = hardcoded/embedded
    expect_pq: bool = False         # endpoint is *supposed* to negotiate hybrid/PQ key exchange
    notes: str = ""

    @property
    def display_name(self) -> str:
        base = f"{self.host}:{self.port}"
        return f"{self.label} ({base})" if self.label else base


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    quantum_risk: QuantumRisk
    category: str                   # inventory | deprecated | hndl | downgrade | expiry | pqc | code-* | secret
    host: str
    port: int
    description: str
    evidence: str = ""
    recommendation: str = ""
    references: list[str] = field(default_factory=list)
    location: str = ""              # for code findings: "path/to/file:line"


@dataclass
class Scores:
    risk_score: int                 # 0..100 — overall urgency to migrate (higher = sooner)
    hndl_risk: int                  # 0..100 — harvest-now-decrypt-later exposure
    migration_difficulty: int       # 0..100 — how hard the migration will be
    readiness: int                  # 0..100 — how PQC-ready the endpoint already is
    priority: str                   # NOW | SOON | LATER | OK


@dataclass
class EndpointReport:
    profile: AssetProfile
    scan: ScanResult
    findings: list[Finding] = field(default_factory=list)
    scores: Optional[Scores] = None


def to_serializable(obj: Any) -> Any:
    """Recursively convert dataclasses / enums / containers into JSON-safe
    primitives. Enums render as their lowercase label, not their integer value,
    so downstream SIEM content is human-readable."""

    if isinstance(obj, IntEnum):
        return obj.label
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_serializable(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, dict):
        return {str(k): to_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [to_serializable(v) for v in obj]
    return obj


# --------------------------------------------------------------------------- #
# Deserialization: rebuild dataclasses from a serialized report (the inverse of
# ``to_serializable``), so ``qer export`` can re-emit any format from a saved
# JSON report without re-scanning. Enum fields arrive as their lowercase labels.
# --------------------------------------------------------------------------- #

def crypto_primitive_from_dict(d: dict) -> CryptoPrimitive:
    return CryptoPrimitive(
        role=d.get("role", ""), algorithm=d.get("algorithm", ""),
        quantum_risk=QuantumRisk.from_label(d.get("quantum_risk", QuantumRisk.PQ_SAFE)),
        detail=d.get("detail", ""), bits=d.get("bits"),
        forward_secret=d.get("forward_secret"), note=d.get("note", ""))


def cert_info_from_dict(d: dict) -> CertInfo:
    return CertInfo(
        subject=d.get("subject", ""), issuer=d.get("issuer", ""), serial=d.get("serial", ""),
        public_key_algorithm=d.get("public_key_algorithm", ""),
        signature_algorithm=d.get("signature_algorithm", ""),
        position=d.get("position", "leaf"), is_ca=bool(d.get("is_ca", False)),
        is_self_signed=bool(d.get("is_self_signed", False)),
        not_before=d.get("not_before"), not_after=d.get("not_after"),
        days_to_expiry=d.get("days_to_expiry"), public_key_bits=d.get("public_key_bits"),
        public_key_curve=d.get("public_key_curve"), signature_hash=d.get("signature_hash"),
        sans=list(d.get("sans", [])),
        quantum_risk=QuantumRisk.from_label(d.get("quantum_risk", QuantumRisk.PQ_SAFE)))


def scan_result_from_dict(d: dict) -> ScanResult:
    return ScanResult(
        host=d.get("host", ""), port=int(d.get("port", 443)),
        reachable=bool(d.get("reachable", False)), error=d.get("error"), ip=d.get("ip"),
        negotiated_version=d.get("negotiated_version"), negotiated_cipher=d.get("negotiated_cipher"),
        supported_versions=list(d.get("supported_versions", [])),
        weak_versions=list(d.get("weak_versions", [])),
        key_exchange=d.get("key_exchange"), authentication=d.get("authentication"),
        forward_secret=d.get("forward_secret"),
        primitives=[crypto_primitive_from_dict(x) for x in d.get("primitives", [])],
        certificates=[cert_info_from_dict(x) for x in d.get("certificates", [])],
        pq_kex_negotiated=d.get("pq_kex_negotiated"), pq_testable=bool(d.get("pq_testable", False)),
        pq_groups_supported=list(d.get("pq_groups_supported", [])),
        pq_preferred=d.get("pq_preferred"), openssl_version=d.get("openssl_version", ""),
        scanned_at=d.get("scanned_at"))


def asset_profile_from_dict(d: dict) -> AssetProfile:
    return AssetProfile(
        host=d.get("host", ""), port=int(d.get("port", 443)), label=d.get("label", ""),
        sensitivity=int(d.get("sensitivity", 3)), shelf_life_years=int(d.get("shelf_life_years", 5)),
        exposure=Exposure.parse(d.get("exposure", Exposure.EXTERNAL)),
        crypto_agility=int(d.get("crypto_agility", 3)),
        expect_pq=bool(d.get("expect_pq", False)), notes=d.get("notes", ""))


def finding_from_dict(d: dict) -> Finding:
    return Finding(
        id=d.get("id", ""), title=d.get("title", ""),
        severity=Severity.from_label(d.get("severity", Severity.INFO)),
        quantum_risk=QuantumRisk.from_label(d.get("quantum_risk", QuantumRisk.PQ_SAFE)),
        category=d.get("category", ""), host=d.get("host", ""), port=int(d.get("port", 0)),
        description=d.get("description", ""), evidence=d.get("evidence", ""),
        recommendation=d.get("recommendation", ""), references=list(d.get("references", [])),
        location=d.get("location", ""))


def scores_from_dict(d: Optional[dict]) -> Optional[Scores]:
    if not d:
        return None
    return Scores(
        risk_score=int(d.get("risk_score", 0)), hndl_risk=int(d.get("hndl_risk", 0)),
        migration_difficulty=int(d.get("migration_difficulty", 0)),
        readiness=int(d.get("readiness", 0)), priority=d.get("priority", "OK"))


def endpoint_report_from_dict(d: dict) -> EndpointReport:
    return EndpointReport(
        profile=asset_profile_from_dict(d.get("profile", {})),
        scan=scan_result_from_dict(d.get("scan", {})),
        findings=[finding_from_dict(x) for x in d.get("findings", [])],
        scores=scores_from_dict(d.get("scores")))


def reports_from_document(doc: dict) -> list[EndpointReport]:
    """Rebuild the endpoint reports from a full QER JSON report document.

    Tolerant of a malformed but valid-JSON document: a non-list ``endpoints``
    raises ValueError (caught by the CLI), and non-dict elements are skipped
    rather than crashing with AttributeError."""
    if not isinstance(doc, dict) or "endpoints" not in doc:
        raise ValueError("not a QER scan report (missing 'endpoints')")
    endpoints = doc["endpoints"]
    if not isinstance(endpoints, list):
        raise ValueError("'endpoints' must be a list")
    return [endpoint_report_from_dict(e) for e in endpoints if isinstance(e, dict)]
