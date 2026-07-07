"""Hybrid/PQ downgrade monitor.

Two complementary mechanisms:

1. **Live posture checks** — forward-secrecy loss and legacy-version acceptance
   are detected on every scan (these live in :mod:`qer.scoring`).

2. **Baseline diffing** — the core of a *monitor*. We snapshot each endpoint's
   crypto posture and, on re-scan, alert when it regresses: the negotiated TLS
   version drops, forward secrecy is lost, the bulk cipher or key shrinks, or a
   previously-negotiated post-quantum/hybrid key-exchange group disappears.

The PQ-group regression is the "hybrid TLS downgrade" the spec calls for: if an
endpoint negotiated X25519MLKEM768 last week and only classical X25519 today,
that is a downgrade worth paging on — whether caused by a config rollback, a
load-balancer swap, or an active attacker stripping the PQ key share.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Optional

from .classify import classify_protocol
from .models import EndpointReport, Finding, QuantumRisk, ScanResult, Severity

BASELINE_VERSION = 1

# Higher rank = stronger/newer protocol. Used to detect a version *drop*.
_VERSION_RANK = {
    "SSLv2": 0, "SSLv3": 1,
    "TLSv1": 2, "TLSv1.0": 2, "TLSv1.1": 3, "TLSv1.2": 4, "TLSv1.3": 5,
}


def endpoint_key(host: str, port: int) -> str:
    return f"{host}:{port}"


def snapshot(scan: ScanResult) -> dict:
    """A compact, comparable record of an endpoint's crypto posture."""
    cert = scan.certificates[0] if scan.certificates else None
    return {
        "negotiated_version": scan.negotiated_version,
        "supported_versions": sorted(scan.supported_versions),
        "weak_versions": sorted(scan.weak_versions),
        "cipher": scan.negotiated_cipher,
        "key_exchange": scan.key_exchange,
        "forward_secret": scan.forward_secret,
        "cipher_bits": next((p.bits for p in scan.primitives if p.role == "cipher"), None),
        "cert_key_alg": cert.public_key_algorithm if cert else None,
        "cert_key_bits": cert.public_key_bits if cert else None,
        "cert_sig_alg": cert.signature_algorithm if cert else None,
        "pq_kex_negotiated": scan.pq_kex_negotiated,
        "pq_groups_supported": sorted(scan.pq_groups_supported),
        "pq_preferred": scan.pq_preferred,
        "scanned_at": scan.scanned_at,
    }


def build_baseline(reports: list[EndpointReport]) -> dict:
    return {
        "_meta": {
            "version": BASELINE_VERSION,
            "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "endpoints": len(reports),
        },
        "endpoints": {
            endpoint_key(r.scan.host, r.scan.port): snapshot(r.scan)
            for r in reports if r.scan.reachable
        },
    }


def save_baseline(baseline: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(baseline, fh, indent=2)


def load_baseline(path: str) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _rank(version: Optional[str]) -> Optional[int]:
    return _VERSION_RANK.get(version) if version else None


def compare(scan: ScanResult, prev: dict) -> list[Finding]:
    """Diff a fresh scan against a previous snapshot; emit regression findings."""
    host, port = scan.host, scan.port
    out: list[Finding] = []

    def add(fid, title, desc, evidence, risk=QuantumRisk.QUANTUM_VULNERABLE, sev=Severity.HIGH):
        out.append(Finding(
            id=fid, title=title, severity=sev, quantum_risk=risk,
            category="downgrade", host=host, port=port,
            description=desc, evidence=evidence,
            recommendation="Investigate the configuration change; confirm it was intentional and not an attack or rollback.",
        ))

    # Protocol version downgrade. Label the risk by the version we *landed on*: a
    # drop to TLS 1.0/1.1 is broken-now, whereas TLS 1.3 -> 1.2 is merely
    # quantum-vulnerable — hardcoding broken-now would mislabel the latter.
    new_rank, old_rank = _rank(scan.negotiated_version), _rank(prev.get("negotiated_version"))
    if new_rank is not None and old_rank is not None and new_rank < old_rank:
        landed_risk = classify_protocol(scan.negotiated_version)[0]
        add("QER-DG-PROTO", "TLS version downgrade detected",
            f"Negotiated TLS version dropped from {prev.get('negotiated_version')} to {scan.negotiated_version}.",
            f"{prev.get('negotiated_version')} -> {scan.negotiated_version}",
            risk=max(landed_risk, QuantumRisk.QUANTUM_VULNERABLE))

    # New legacy versions accepted
    new_weak = set(scan.weak_versions) - set(prev.get("weak_versions", []))
    if new_weak:
        add("QER-DG-LEGACY", "Newly-accepted legacy TLS versions",
            f"Endpoint now accepts legacy versions it did not before: {', '.join(sorted(new_weak))}.",
            f"new weak versions: {', '.join(sorted(new_weak))}",
            risk=QuantumRisk.BROKEN_NOW)

    # Forward secrecy lost
    if prev.get("forward_secret") is True and scan.forward_secret is False:
        add("QER-DG-FS", "Forward secrecy lost",
            "Key exchange regressed from a forward-secret suite to one without forward secrecy "
            f"(now {scan.key_exchange}).",
            f"forward_secret True -> False; kex now {scan.key_exchange}")

    # PQ / hybrid key exchange disappeared — the headline hybrid-downgrade alert.
    # Gated on pq_testable + strict `is False` so re-scanning with --no-pq (which
    # leaves pq_kex_negotiated=None, i.e. "not tested") never fires a false alert.
    if scan.pq_testable and prev.get("pq_kex_negotiated") is True and scan.pq_kex_negotiated is False:
        add("QER-DG-PQ", "Post-quantum/hybrid key exchange downgrade",
            "This endpoint previously negotiated a post-quantum/hybrid key-exchange group but now "
            "falls back to classical-only. Recorded traffic is again HNDL-exposed.",
            f"pq_kex_negotiated True -> {scan.pq_kex_negotiated}; cipher now {scan.negotiated_cipher}",
            sev=Severity.CRITICAL)
    # PQ still supported but no longer enforced — a weakening, not a full loss
    elif scan.pq_testable and prev.get("pq_preferred") is True and scan.pq_preferred is False:
        add("QER-DG-PQ-ENFORCE", "Post-quantum enforcement relaxed",
            "This endpoint previously enforced (HRR-upgraded) a hybrid PQ group but now accepts a "
            "classical key exchange when the client offers one. The classical-client population is "
            "HNDL-exposed again.",
            "pq_preferred True -> False",
            risk=QuantumRisk.QUANTUM_VULNERABLE, sev=Severity.HIGH)

    # Bulk cipher shrank
    new_bits = next((p.bits for p in scan.primitives if p.role == "cipher"), None)
    old_bits = prev.get("cipher_bits")
    if new_bits and old_bits and new_bits < old_bits:
        add("QER-DG-CIPHER", "Bulk cipher strength reduced",
            f"Negotiated symmetric strength dropped from {old_bits} to {new_bits} bits.",
            f"cipher_bits {old_bits} -> {new_bits} ({prev.get('cipher')} -> {scan.negotiated_cipher})",
            risk=QuantumRisk.QUANTUM_WEAKENED)

    # Certificate key shrank
    cert = scan.certificates[0] if scan.certificates else None
    if cert and cert.public_key_bits and prev.get("cert_key_bits"):
        if cert.public_key_bits < prev["cert_key_bits"]:
            add("QER-DG-KEY", "Certificate key size reduced",
                f"Leaf certificate key shrank from {prev['cert_key_bits']} to {cert.public_key_bits} bits.",
                f"cert_key_bits {prev['cert_key_bits']} -> {cert.public_key_bits}")

    return out


def diff_reports(reports: list[EndpointReport], baseline: dict) -> int:
    """Attach downgrade findings to each report in place. Returns count added."""
    endpoints = (baseline or {}).get("endpoints", {})
    added = 0
    for r in reports:
        if not r.scan.reachable:
            continue
        prev = endpoints.get(endpoint_key(r.scan.host, r.scan.port))
        if not prev:
            continue
        new_findings = compare(r.scan, prev)
        r.findings.extend(new_findings)
        added += len(new_findings)
    return added
