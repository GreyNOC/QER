"""Active TLS endpoint scanner.

Performs real handshakes against a target and records, factually, what was
negotiated: protocol version range, cipher suite, key exchange, forward secrecy,
and the leaf certificate's public key + signature algorithm. Everything is then
classified by :mod:`qer.classify` into a per-endpoint cryptographic bill of
materials (CBOM).

Post-quantum support is established by :mod:`qer.pqprobe`, a dependency-free raw
TLS 1.3 probe that works on any OpenSSL (the stdlib ``ssl`` module has no API to
offer key-exchange groups, so the negotiated cipher alone cannot reveal PQ
support). The probe sets ``pq_testable``, ``pq_kex_negotiated`` and
``pq_groups_supported`` on the result.

Honesty about remaining limits (documented, never silently hidden):

* Only the leaf certificate is parsed (stdlib does not expose the full chain on
  3.11). Intermediate/root inventory is a roadmap item.
* The PQ probe establishes *support* for a hybrid group, which is what governs
  whether PQ-capable clients get PQ protection; it does not measure what a
  specific legacy client would negotiate.
"""

from __future__ import annotations

import datetime as dt
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable, Optional

from .cert_chain import fetch_certificate_chain
from .classify import (classify_protocol, classify_public_key,
                       classify_signature, parse_cipher)
from .models import (AssetProfile, CertInfo, CryptoPrimitive, QuantumRisk,
                     ScanResult)
from .pqprobe import probe_pq
from .starttls import negotiate as starttls_negotiate
from .starttls import resolve_dialect

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import (dsa, ec, ed448,
                                                           ed25519, rsa)
    HAVE_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover - exercised only when dependency missing
    HAVE_CRYPTOGRAPHY = False


# Probe newest -> oldest. SSLv3 is included so we can *detect* (and condemn) it.
_VERSION_PROBES = [
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
]
if hasattr(ssl.TLSVersion, "SSLv3"):
    _VERSION_PROBES.append(("SSLv3", ssl.TLSVersion.SSLv3))


def _is_ip_literal(host: str) -> bool:
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, host)
            return True
        except OSError:
            continue
    return False


def _permissive_context(min_v=None, max_v=None, seclevel0: bool = False) -> ssl.SSLContext:
    """A context that will complete a handshake with almost anything so we can
    *inventory* it — we are not validating trust, we are taking attendance."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if min_v is not None:
        try:
            ctx.minimum_version = min_v
        except (ValueError, OSError):
            pass
    if max_v is not None:
        try:
            ctx.maximum_version = max_v
        except (ValueError, OSError):
            pass
    if seclevel0:
        # SECLEVEL=0 lets us detect legacy protocols/ciphers OpenSSL would
        # otherwise refuse, so weak-config detection isn't a false negative.
        for spec in ("ALL:@SECLEVEL=0", "ALL:COMPLEMENTOFDEFAULT:@SECLEVEL=0"):
            try:
                ctx.set_ciphers(spec)
                break
            except ssl.SSLError:
                continue
    return ctx


def _connect(host: str, port: int, ctx: ssl.SSLContext, timeout: float,
             starttls: Optional[str] = None):
    """Open a (optionally STARTTLS-upgraded) TLS connection and return the
    wrapped socket (caller closes)."""
    server_hostname = None if _is_ip_literal(host) else host
    raw = socket.create_connection((host, port), timeout=timeout)
    raw.settimeout(timeout)
    try:
        if starttls:
            starttls_negotiate(raw, starttls, host, timeout)
        return ctx.wrap_socket(raw, server_hostname=server_hostname)
    except Exception:
        raw.close()
        raise


def _parse_certificate(der: bytes) -> CertInfo:
    """Parse a DER certificate into a classified ``CertInfo`` using cryptography."""
    cert = x509.load_der_x509_certificate(der)

    pk = cert.public_key()
    curve = None
    if isinstance(pk, rsa.RSAPublicKey):
        alg, bits = "RSA", pk.key_size
    elif isinstance(pk, ec.EllipticCurvePublicKey):
        alg, bits, curve = "ECDSA", pk.key_size, pk.curve.name
    elif isinstance(pk, ed25519.Ed25519PublicKey):
        alg, bits, curve = "Ed25519", 256, "ed25519"
    elif isinstance(pk, ed448.Ed448PublicKey):
        alg, bits, curve = "Ed448", 448, "ed448"
    elif isinstance(pk, dsa.DSAPublicKey):
        alg, bits = "DSA", pk.key_size
    else:
        alg, bits = type(pk).__name__, getattr(pk, "key_size", None)

    try:
        sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except Exception:
        sig_hash = None
    sig_alg_name = getattr(cert.signature_algorithm_oid, "_name", None) \
        or cert.signature_algorithm_oid.dotted_string

    pk_risk, _, _ = classify_public_key(alg, bits, curve)
    sig_risk, _, sig_hash_detected, _ = classify_signature(sig_alg_name)

    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = list(ext.value.get_values_for_type(x509.DNSName))
    except Exception:
        pass

    is_ca = False
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        is_ca = bool(bc.value.ca)
    except Exception:
        pass

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    now = dt.datetime.now(dt.timezone.utc)
    days_to_expiry = (not_after - now).days

    return CertInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial=format(cert.serial_number, "x"),
        public_key_algorithm=alg,
        signature_algorithm=sig_alg_name,
        is_ca=is_ca,
        is_self_signed=cert.subject == cert.issuer,
        not_before=not_before.isoformat(),
        not_after=not_after.isoformat(),
        days_to_expiry=days_to_expiry,
        public_key_bits=bits,
        public_key_curve=curve,
        signature_hash=sig_hash or sig_hash_detected,
        sans=sans,
        quantum_risk=max(pk_risk, sig_risk),
    )


def _parse_chain(der_list) -> list[CertInfo]:
    """Parse a list of DER certs into CertInfo, labelling position by the index
    within the *surviving* (successfully parsed) list — so a parse failure on the
    leaf doesn't shift the 'leaf' label onto a CA."""
    chain_infos: list[CertInfo] = []
    for dcert in der_list:
        try:
            ci = _parse_certificate(dcert)
        except Exception:
            continue
        ci.position = ("leaf" if not chain_infos
                       else ("root" if ci.is_self_signed else "intermediate"))
        chain_infos.append(ci)
    return chain_infos


def _certinfo_from_stdlib(cert_dict: dict) -> Optional[CertInfo]:
    """Fallback when cryptography is unavailable: stdlib gives identity + dates
    but not the public-key algorithm, so risk is left unknown-but-flagged."""
    if not cert_dict:
        return None

    def _join(seq):
        return ", ".join("=".join(p) for rdn in seq for p in rdn)

    sans = [v for (t, v) in cert_dict.get("subjectAltName", ()) if t == "DNS"]
    not_after = cert_dict.get("notAfter")
    return CertInfo(
        subject=_join(cert_dict.get("subject", ())),
        issuer=_join(cert_dict.get("issuer", ())),
        serial=str(cert_dict.get("serialNumber", "")),
        public_key_algorithm="unknown (install 'cryptography' for key analysis)",
        signature_algorithm="unknown",
        not_after=not_after,
        sans=sans,
        quantum_risk=QuantumRisk.QUANTUM_VULNERABLE,
    )


def _enumerate_versions(host: str, port: int, timeout: float,
                        starttls: Optional[str] = None) -> tuple[list[str], list[str]]:
    """Probe each protocol version individually. Returns (supported, weak)."""
    supported, weak = [], []
    for label, ver in _VERSION_PROBES:
        ctx = _permissive_context(min_v=ver, max_v=ver, seclevel0=True)
        try:
            s = _connect(host, port, ctx, timeout, starttls=starttls)
            negotiated = s.version()
            s.close()
            if negotiated:
                supported.append(label)
                if classify_protocol(label)[0] == QuantumRisk.BROKEN_NOW:
                    weak.append(label)
        except Exception:
            continue
    return supported, weak


def scan_endpoint(profile: AssetProfile, timeout: float = 6.0,
                  enumerate_versions: bool = True, do_pq_probe: bool = True,
                  pq_groups: Optional[list] = None, do_chain: bool = True) -> ScanResult:
    """Scan one endpoint and return a factual ``ScanResult``."""
    host, port = profile.host, profile.port
    starttls = resolve_dialect(profile.starttls, port)
    result = ScanResult(
        host=host, port=port,
        openssl_version=ssl.OPENSSL_VERSION,
        scanned_at=dt.datetime.now(dt.timezone.utc).isoformat(),
        pq_testable=False,
        pq_kex_negotiated=None,
        starttls=starttls,
    )

    try:
        result.ip = socket.gethostbyname(host)
    except Exception:
        result.ip = None

    # --- primary handshake: what does the server actually prefer? ---
    try:
        ctx = _permissive_context()
        sock = _connect(host, port, ctx, timeout, starttls=starttls)
    except Exception as exc:
        result.reachable = False
        result.error = f"{type(exc).__name__}: {exc}"
        return result

    try:
        result.reachable = True
        result.negotiated_version = sock.version()
        cipher_tuple = sock.cipher()             # (name, protocol, secret_bits)
        der = sock.getpeercert(binary_form=True)
        std_dict = {} if HAVE_CRYPTOGRAPHY else sock.getpeercert()
    finally:
        sock.close()

    # --- protocol primitive ---
    if result.negotiated_version:
        prot_risk, _, prot_note = classify_protocol(result.negotiated_version)
        result.primitives.append(CryptoPrimitive(
            role="protocol", algorithm=result.negotiated_version,
            quantum_risk=prot_risk, note=prot_note,
        ))

    # --- cipher suite primitives ---
    if cipher_tuple:
        profile_c = parse_cipher(cipher_tuple[0])
        if profile_c:
            result.negotiated_cipher = profile_c.name
            result.key_exchange = profile_c.key_exchange
            result.authentication = profile_c.authentication
            result.forward_secret = profile_c.forward_secret
            for prim in profile_c.primitives:
                if prim.role == "cipher" and cipher_tuple[2]:
                    prim.bits = prim.bits or cipher_tuple[2]
                result.primitives.append(prim)

    # --- certificate(s): stdlib gives the leaf; the raw TLS 1.2 probe gives the
    #     full presented chain (leaf + intermediates) when the server speaks 1.2.
    leaf_info: Optional[CertInfo] = None
    if der and HAVE_CRYPTOGRAPHY:
        try:
            leaf_info = _parse_certificate(der)
        except Exception as exc:
            result.error = f"certificate parse failed: {exc}"
    elif not HAVE_CRYPTOGRAPHY:
        leaf_info = _certinfo_from_stdlib(std_dict)

    chain_infos: list[CertInfo] = []
    if do_chain and HAVE_CRYPTOGRAPHY:
        chain_infos = _parse_chain(
            fetch_certificate_chain(host, port, timeout=timeout, starttls=starttls))

    if chain_infos:
        result.certificates = chain_infos
    elif leaf_info:
        result.certificates = [leaf_info]

    if result.certificates:
        leaf = result.certificates[0]
        result.primitives.append(CryptoPrimitive(
            role="certificate-key",
            algorithm=(f"{leaf.public_key_algorithm}-{leaf.public_key_bits}"
                       if leaf.public_key_bits else leaf.public_key_algorithm),
            quantum_risk=leaf.quantum_risk,
            detail=leaf.public_key_curve or "",
            bits=leaf.public_key_bits,
            note=f"Leaf certificate key; signed with {leaf.signature_algorithm}."
                 + (f" Chain depth {len(result.certificates)}." if len(result.certificates) > 1 else ""),
        ))

    # --- version range enumeration ---
    if enumerate_versions:
        supported, weak = _enumerate_versions(host, port, timeout, starttls=starttls)
        result.supported_versions = supported
        result.weak_versions = weak
        for label in weak:
            prot_risk, _, prot_note = classify_protocol(label)
            result.primitives.append(CryptoPrimitive(
                role="protocol", algorithm=label, quantum_risk=prot_risk,
                note=f"Legacy protocol accepted: {prot_note}",
            ))
    elif result.negotiated_version:
        result.supported_versions = [result.negotiated_version]

    # --- active post-quantum / hybrid key-exchange probe ---
    if do_pq_probe:
        pq = probe_pq(host, port, timeout=timeout, groups=pq_groups, starttls=starttls)
        result.pq_testable = pq["testable"]
        result.pq_groups_supported = pq["supported_groups"]
        result.pq_kex_negotiated = pq["pq_supported"]
        result.pq_preferred = pq.get("pq_preferred")
        if pq["supported_groups"]:
            enforced = " enforced" if result.pq_preferred else " (classical accepted)"
            result.primitives.append(CryptoPrimitive(
                role="key-exchange",
                algorithm="+".join(pq["supported_groups"]),
                quantum_risk=QuantumRisk.PQ_SAFE, forward_secret=True,
                note=f"Server offers post-quantum/hybrid key exchange (actively probed){enforced}.",
            ))

    return result


def discover_services(hosts: Iterable[str], ports: Iterable[int],
                      timeout: float = 2.0, workers: int = 64,
                      progress=None) -> list[tuple[str, int]]:
    """Concurrent TCP connect-scan across ``hosts`` × ``ports``. Returns the open
    ``(host, port)`` pairs (sorted), so a CIDR sweep can find live TLS/STARTTLS
    services before the (much heavier) deep crypto scan runs on just those."""
    pairs = [(h, int(p)) for h in hosts for p in ports]
    if not pairs:
        return []

    def _check(hp: tuple[str, int]) -> Optional[tuple[str, int]]:
        host, port = hp
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            return hp
        except OSError:
            return None

    open_pairs: list[tuple[str, int]] = []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(pairs)))) as pool:
        futures = {pool.submit(_check, hp): hp for hp in pairs}
        for fut in as_completed(futures):
            hp = futures[fut]
            try:
                res = fut.result()
            except Exception:
                res = None
            if res:
                open_pairs.append(res)
            if progress:
                progress(hp, res is not None)
    return sorted(open_pairs)


def scan_targets(profiles: Iterable[AssetProfile], timeout: float = 6.0,
                 enumerate_versions: bool = True, workers: int = 16,
                 do_pq_probe: bool = True, pq_groups: Optional[list] = None,
                 do_chain: bool = True, progress=None) -> list[ScanResult]:
    """Scan many endpoints concurrently, preserving input order."""
    profiles = list(profiles)
    results: list[Optional[ScanResult]] = [None] * len(profiles)
    workers = max(1, min(workers, len(profiles) or 1))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(scan_endpoint, p, timeout, enumerate_versions,
                        do_pq_probe, pq_groups, do_chain): i
            for i, p in enumerate(profiles)
        }
        for fut in as_completed(futures):
            i = futures[fut]
            try:
                results[i] = fut.result()
            except Exception as exc:
                results[i] = ScanResult(
                    host=profiles[i].host, port=profiles[i].port,
                    reachable=False, error=f"{type(exc).__name__}: {exc}",
                )
            if progress:
                progress(profiles[i], results[i])

    return [r for r in results if r is not None]
