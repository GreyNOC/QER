"""Scoring and finding generation.

Turns the *facts* a scan observed plus the *business context* in an
``AssetProfile`` into the numbers executives and SIEMs actually act on:

* **HNDL risk** — "harvest now, decrypt later" exposure. The marquee metric.
  It is driven specifically by quantum-vulnerable *key exchange* (which lets an
  adversary decrypt recorded traffic once a CRQC exists), weighted by how long
  the data must stay secret (Mosca's inequality: secrecy lifetime + migration
  time vs. time-to-CRQC), its sensitivity, and its exposure.
* **risk_score** — overall migration urgency, folding HNDL together with
  present-day hygiene problems (legacy TLS, no forward secrecy, weak ciphers).
* **migration_difficulty** — mostly the inverse of crypto agility.
* **readiness** — how modern/agile the endpoint already is (a quick-win signal).
* **priority** — NOW / SOON / LATER / OK bucket derived from risk_score.

Signatures and certificate keys are quantum-vulnerable too, but they are *not*
HNDL-relevant: you cannot retroactively forge a signature over traffic that was
already accepted. They drive migration urgency (future impersonation), not the
harvest-now metric. Keeping that distinction correct is the point of the tool.
"""

from __future__ import annotations

from .classify import is_pq_algorithm
from .models import (AssetProfile, Finding, QuantumRisk, ScanResult, Scores,
                     Severity)

REF_NIST_PQC = "https://csrc.nist.gov/projects/post-quantum-cryptography"
REF_MOSCA = "https://eprint.iacr.org/2015/1075"          # Mosca, "Cybersecurity in an era with quantum computers"
REF_RFC8996 = "https://www.rfc-editor.org/rfc/rfc8996"   # Deprecating TLS 1.0/1.1
REF_CNSA2 = "https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/3148990/"  # CNSA 2.0 timeline

EXPIRY_WARN_DAYS = 30


def _clamp(x: float, lo: int = 0, hi: int = 100) -> int:
    return int(max(lo, min(hi, round(x))))


def _kex_hndl_factor(scan: ScanResult) -> float:
    """How exposed *recorded* traffic is to future decryption (0..1)."""
    kex = scan.key_exchange or ""
    if is_pq_algorithm(kex):
        return 0.0
    # Server actively proven to support a hybrid PQ group. If it *enforces* PQ
    # (HRR-upgrades any PQ-advertising client) the residual is only truly-legacy
    # clients that never offer PQ; if it merely *tolerates* PQ (accepts classical
    # when offered) the exposed population is larger.
    if scan.pq_preferred:
        return 0.05
    if scan.pq_kex_negotiated:
        return 0.15
    if kex == "PSK":
        return 0.0           # plain PSK has no Shor-breakable handshake -> not HNDL-exposed
    if scan.forward_secret is False:        # RSA key transport / static (EC)DH
        return 1.0
    if kex in ("ECDHE", "DHE"):             # forward secret classically, but Shor breaks the recorded handshake
        return 0.8
    return 0.7


def hndl_risk(profile: AssetProfile, scan: ScanResult) -> int:
    if not scan.reachable:
        return 0
    kex_factor = _kex_hndl_factor(scan)
    if kex_factor == 0.0:
        return 0
    f_shelf = min(profile.shelf_life_years / 10.0, 1.0)
    f_sensitivity = profile.sensitivity / 5.0
    f_exposure = int(profile.exposure) / 3.0
    context = 0.45 * f_shelf + 0.30 * f_sensitivity + 0.25 * f_exposure
    return _clamp(100 * kex_factor * context)


def _hygiene_urgency(scan: ScanResult) -> int:
    """Present-day (non-quantum) urgency from configuration hygiene."""
    score = 0
    if scan.weak_versions:
        score = max(score, 85)
    if scan.dominant_risk() == QuantumRisk.BROKEN_NOW:
        score = max(score, 80)
    if scan.forward_secret is False:
        score = max(score, 55)
    for c in scan.certificates:
        if c.days_to_expiry is not None and c.days_to_expiry < 0:
            score = max(score, 75)
        elif c.days_to_expiry is not None and c.days_to_expiry < EXPIRY_WARN_DAYS:
            score = max(score, 50)
    return score


def migration_difficulty(profile: AssetProfile, scan: ScanResult) -> int:
    base = (5 - profile.crypto_agility) / 4.0 * 100      # agility 5 -> 0, agility 1 -> 100
    if scan.reachable and scan.dominant_risk() == QuantumRisk.BROKEN_NOW:
        base += 10                                        # legacy stacks are usually harder to move
    return _clamp(base)


def readiness(scan: ScanResult, profile: AssetProfile) -> int:
    """How modern/agile the endpoint already is — a quick-win signal, not a
    claim that it is post-quantum."""
    if not scan.reachable:
        return 0
    if scan.pq_kex_negotiated:
        return 100
    score = 0.0
    if "TLSv1.3" in scan.supported_versions and not scan.weak_versions:
        score += 30
    elif "TLSv1.3" in scan.supported_versions:
        score += 15
    if scan.forward_secret:
        score += 20
    cipher_pq_safe = any(p.role == "cipher" and p.quantum_risk == QuantumRisk.PQ_SAFE
                         for p in scan.primitives)
    if cipher_pq_safe:
        score += 15
    if scan.dominant_risk() != QuantumRisk.BROKEN_NOW:
        score += 15
    score += profile.crypto_agility / 5.0 * 20
    return _clamp(score)


def _priority(risk_score: int) -> str:
    if risk_score >= 70:
        return "NOW"
    if risk_score >= 45:
        return "SOON"
    if risk_score >= 20:
        return "LATER"
    return "OK"


def score_endpoint(profile: AssetProfile, scan: ScanResult) -> Scores:
    if not scan.reachable:
        return Scores(risk_score=0, hndl_risk=0, migration_difficulty=0,
                      readiness=0, priority="UNREACHABLE")

    hndl = hndl_risk(profile, scan)
    hygiene = _hygiene_urgency(scan)
    sig_exposure = 50 if any(c.quantum_risk >= QuantumRisk.QUANTUM_VULNERABLE
                             for c in scan.certificates) else 0

    f_exposure = int(profile.exposure) / 3.0
    f_sensitivity = profile.sensitivity / 5.0
    context_mult = 0.75 + 0.25 * ((f_exposure + f_sensitivity) / 2.0)

    risk = max(hndl, hygiene, sig_exposure) * context_mult
    risk_score = _clamp(risk)

    return Scores(
        risk_score=risk_score,
        hndl_risk=hndl,
        migration_difficulty=migration_difficulty(profile, scan),
        readiness=readiness(scan, profile),
        priority=_priority(risk_score),
    )


# --------------------------------------------------------------------------- #
# Finding generation
# --------------------------------------------------------------------------- #

def _sev_from_hndl(h: int) -> Severity:
    if h >= 75:
        return Severity.CRITICAL
    if h >= 50:
        return Severity.HIGH
    if h >= 25:
        return Severity.MEDIUM
    return Severity.LOW


def generate_findings(profile: AssetProfile, scan: ScanResult, scores: Scores) -> list[Finding]:
    host, port = scan.host, scan.port
    out: list[Finding] = []

    if not scan.reachable:
        out.append(Finding(
            id="QER-UNREACHABLE", title="Endpoint not reachable over TLS",
            severity=Severity.INFO, quantum_risk=QuantumRisk.PQ_SAFE,
            category="inventory", host=host, port=port,
            description=f"No TLS handshake could be completed: {scan.error}",
            recommendation="Confirm host/port and that the service speaks TLS.",
        ))
        return out

    # Legacy protocol versions
    if scan.weak_versions:
        out.append(Finding(
            id="QER-PROTO-LEGACY",
            title=f"Legacy TLS versions accepted: {', '.join(scan.weak_versions)}",
            severity=Severity.HIGH, quantum_risk=QuantumRisk.BROKEN_NOW,
            category="deprecated", host=host, port=port,
            description="The endpoint completed handshakes using TLS versions deprecated by RFC 8996.",
            evidence=f"Accepted versions: {', '.join(scan.weak_versions)}",
            recommendation="Disable TLS 1.1 and below; require TLS 1.2+ (prefer 1.3).",
            references=[REF_RFC8996],
        ))

    # No forward secrecy
    if scan.forward_secret is False:
        out.append(Finding(
            id="QER-NOFS",
            title="No forward secrecy (static/RSA key transport)",
            severity=Severity.HIGH, quantum_risk=QuantumRisk.QUANTUM_VULNERABLE,
            category="hndl", host=host, port=port,
            description="The negotiated key exchange provides no forward secrecy, so a single "
                        "private-key compromise — classical today or quantum later — exposes all "
                        "recorded sessions at once.",
            evidence=f"Key exchange: {scan.key_exchange}; cipher: {scan.negotiated_cipher}",
            recommendation="Prefer ECDHE/DHE now and hybrid PQ key exchange (e.g. X25519MLKEM768) as it rolls out.",
            references=[REF_NIST_PQC],
        ))

    # Core HNDL finding: quantum-vulnerable key exchange + long-lived data
    kex_factor = _kex_hndl_factor(scan)
    if kex_factor > 0 and scores.hndl_risk > 0:
        out.append(Finding(
            id="QER-HNDL",
            title=f"Harvest-now-decrypt-later exposure (HNDL risk {scores.hndl_risk}/100)",
            severity=_sev_from_hndl(scores.hndl_risk), quantum_risk=QuantumRisk.QUANTUM_VULNERABLE,
            category="hndl", host=host, port=port,
            description=(f"Traffic is protected by quantum-vulnerable key exchange "
                         f"({scan.key_exchange}). An adversary recording it today can decrypt it once a "
                         f"cryptographically relevant quantum computer exists. The data's stated "
                         f"{profile.shelf_life_years}-year shelf life is the multiplier: by Mosca's "
                         f"inequality, secrecy lifetime plus migration time must not exceed time-to-CRQC."),
            evidence=(f"kex={scan.key_exchange} forward_secret={scan.forward_secret} "
                      f"sensitivity={profile.sensitivity}/5 shelf_life={profile.shelf_life_years}y "
                      f"exposure={profile.exposure.label}"),
            recommendation="Prioritise this channel for hybrid/PQ key exchange; shorten data retention where possible.",
            references=[REF_MOSCA, REF_CNSA2],
        ))

    # Certificate chain (CBOM). The leaf drives the quantum-vulnerable finding;
    # the chain gets one inventory finding plus targeted weak-CA / expiry alerts.
    chain = scan.certificates
    leaf = chain[0] if chain else None

    if leaf and leaf.quantum_risk >= QuantumRisk.QUANTUM_VULNERABLE:
        sev = Severity.HIGH if leaf.quantum_risk == QuantumRisk.BROKEN_NOW else Severity.MEDIUM
        out.append(Finding(
            id="QER-CERT-PQ",
            title=f"Quantum-vulnerable certificate ({leaf.public_key_algorithm}"
                  f"{'-' + str(leaf.public_key_bits) if leaf.public_key_bits else ''})",
            severity=sev, quantum_risk=leaf.quantum_risk,
            category="pqc", host=host, port=port,
            description="The leaf certificate's public key and/or signature uses an algorithm "
                        "broken by Shor's algorithm. This drives future-impersonation risk and the "
                        "eventual need for PQ certificate authorities.",
            evidence=f"key={leaf.public_key_algorithm} bits={leaf.public_key_bits} "
                     f"sig={leaf.signature_algorithm} subject={leaf.subject}",
            recommendation="Track CA support for ML-DSA/SLH-DSA certificates; plan reissuance when available.",
            references=[REF_NIST_PQC],
        ))

    if len(chain) > 1:
        key_algs = ", ".join(dict.fromkeys(
            f"{c.public_key_algorithm}{'-' + str(c.public_key_bits) if c.public_key_bits else ''}"
            for c in chain))
        sig_algs = ", ".join(dict.fromkeys(c.signature_algorithm for c in chain))
        out.append(Finding(
            id="QER-CHAIN-CBOM",
            title=f"Certificate chain inventory: {len(chain)} certs (leaf + {len(chain) - 1} CA)",
            severity=Severity.INFO, quantum_risk=max(c.quantum_risk for c in chain),
            category="inventory", host=host, port=port,
            description="Full presented certificate chain captured. Every link's signature must migrate "
                        "to PQ for the chain to be quantum-safe; the chain is only as strong as its weakest CA.",
            evidence="; ".join(f"[{c.position}] {c.public_key_algorithm}"
                               f"{'-' + str(c.public_key_bits) if c.public_key_bits else ''}"
                               f"/{c.signature_algorithm} {c.subject}" for c in chain),
            recommendation=f"Key algs in chain: {key_algs}. Signature algs: {sig_algs}.",
            references=[REF_NIST_PQC],
        ))

    for c in chain:
        if c.position != "leaf" and c.quantum_risk == QuantumRisk.BROKEN_NOW:
            out.append(Finding(
                id="QER-CHAIN-WEAK",
                title=f"Broken cryptography in CA certificate ({c.position}: {c.signature_algorithm})",
                severity=Severity.HIGH, quantum_risk=QuantumRisk.BROKEN_NOW,
                category="deprecated", host=host, port=port,
                description="A CA certificate in the presented chain uses present-day-broken crypto "
                            "(e.g. SHA-1 signature or RSA < 2048). The whole chain inherits this weakness.",
                evidence=f"{c.position}: key={c.public_key_algorithm}"
                         f"{'-' + str(c.public_key_bits) if c.public_key_bits else ''} "
                         f"sig={c.signature_algorithm} subject={c.subject}",
                recommendation="Replace/repath through a CA that signs with SHA-256+ and >=2048-bit keys.",
                references=[REF_RFC8996],
            ))
        if c.days_to_expiry is not None and c.days_to_expiry < 0:
            out.append(Finding(
                id="QER-CERT-EXPIRED", title=f"Certificate is expired ({c.position})",
                severity=Severity.HIGH, quantum_risk=QuantumRisk.PQ_SAFE,
                category="expiry", host=host, port=port,
                description=f"The {c.position} certificate expired {-c.days_to_expiry} day(s) ago.",
                evidence=f"not_after={c.not_after} subject={c.subject}",
                recommendation="Renew/replace the certificate immediately.",
            ))
        elif c.days_to_expiry is not None and c.days_to_expiry < EXPIRY_WARN_DAYS:
            out.append(Finding(
                id="QER-CERT-EXPIRY",
                title=f"Certificate expires in {c.days_to_expiry} day(s) ({c.position})",
                severity=Severity.MEDIUM, quantum_risk=QuantumRisk.PQ_SAFE,
                category="expiry", host=host, port=port,
                description=f"The {c.position} certificate is close to expiry.",
                evidence=f"not_after={c.not_after} subject={c.subject}",
                recommendation="Schedule renewal; verify automated rotation is working.",
            ))

    # Weak symmetric strength for long-lived data
    weak_cipher = next((p for p in scan.primitives
                        if p.role == "cipher" and p.quantum_risk == QuantumRisk.QUANTUM_WEAKENED), None)
    if weak_cipher and profile.shelf_life_years >= 7:
        out.append(Finding(
            id="QER-SYM-128",
            title=f"128-bit symmetric cipher for long-lived data ({weak_cipher.algorithm})",
            severity=Severity.MEDIUM, quantum_risk=QuantumRisk.QUANTUM_WEAKENED,
            category="pqc", host=host, port=port,
            description="Grover's algorithm halves symmetric security; 128-bit ciphers give ~64-bit "
                        "post-quantum margin, which is thin for data that must stay secret for years.",
            evidence=f"cipher={weak_cipher.algorithm} shelf_life={profile.shelf_life_years}y",
            recommendation="Prefer AES-256-GCM or ChaCha20-Poly1305 for long-retention data.",
        ))

    # Post-quantum support (actively probed by qer.pqprobe)
    if scan.pq_groups_supported:
        if scan.pq_preferred:
            desc = ("The server was actively proven to support AND enforce a hybrid PQ key-exchange "
                    "group: it HRR-upgrades clients that advertise PQ even when they offer a classical "
                    "key share. Residual HNDL exposure is limited to clients that never advertise PQ.")
            reco = "Strong posture. Keep enforcing; monitor for regressions via the baseline."
            evidence = f"supported & enforced: {', '.join(scan.pq_groups_supported)}"
        else:
            desc = ("The server supports a hybrid PQ key-exchange group but does NOT enforce it — when a "
                    "client offers a classical key share it completes classically. PQ-capable clients are "
                    "protected, but the classical-only client population is still HNDL-exposed.")
            reco = ("Consider configuring the server to prefer/enforce the hybrid group, and drive client "
                    "fleets to advertise PQ; monitor for regressions.")
            evidence = f"supported (classical accepted): {', '.join(scan.pq_groups_supported)}"
        out.append(Finding(
            id="QER-PQ-OK",
            title=f"Hybrid post-quantum key exchange {'enforced' if scan.pq_preferred else 'supported'} "
                  f"({', '.join(scan.pq_groups_supported)})",
            severity=Severity.INFO, quantum_risk=QuantumRisk.PQ_SAFE,
            category="pqc", host=host, port=port,
            description=desc, evidence=evidence, recommendation=reco, references=[REF_NIST_PQC],
        ))
    elif profile.expect_pq and scan.pq_testable:
        out.append(Finding(
            id="QER-PQ-MISSING",
            title="Expected hybrid/PQ key exchange is NOT supported",
            severity=Severity.HIGH, quantum_risk=QuantumRisk.QUANTUM_VULNERABLE,
            category="downgrade", host=host, port=port,
            description="This asset is flagged expect_pq=true, but an active probe found no hybrid PQ "
                        "key-exchange group. All traffic is on quantum-vulnerable key exchange.",
            evidence=f"probed groups returned none supported; negotiated={scan.negotiated_cipher}",
            recommendation="Enable a hybrid group (e.g. X25519MLKEM768) on the server/load balancer.",
            references=[REF_NIST_PQC],
        ))
    elif profile.expect_pq and not scan.pq_testable:
        out.append(Finding(
            id="QER-PQ-UNVERIFIED",
            title="Expected hybrid/PQ key exchange could not be verified (probe disabled)",
            severity=Severity.MEDIUM, quantum_risk=QuantumRisk.QUANTUM_VULNERABLE,
            category="downgrade", host=host, port=port,
            description="This asset is flagged expect_pq=true, but the active PQ probe was disabled "
                        "(--no-pq), so PQ support was not tested.",
            evidence=f"pq_testable={scan.pq_testable}",
            recommendation="Re-run without --no-pq to actively probe hybrid PQ support.",
            references=[REF_NIST_PQC],
        ))

    return out
