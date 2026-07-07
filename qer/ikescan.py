"""IKEv2 (RFC 7296) IKE_SA_INIT scanner for VPN crypto inventory.

VPN tunnels are a prime "harvest now, decrypt later" target: IPsec key exchange
is classical Diffie-Hellman / ECDH (Shor-vulnerable), and tunnels often carry
long-lived sensitive traffic. This module sends a raw IKE_SA_INIT request that
offers a broad transform proposal and parses the gateway's *chosen* transforms
(encryption, PRF, integrity, Diffie-Hellman group) — or its INVALID_KE_PAYLOAD
group hint — into a cryptographic inventory.

VERIFICATION CAVEAT: unlike every TLS feature in QER, this IKE scanner is
**unit-verified only** (round-trip build/parse against constructed packets). It
has not been proven against a live gateway, because no public IKE responder was
available to test against and UDP/500 egress is often filtered. Treat live IKE
results as best-effort until validated against a known gateway.
"""

from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass, field
from typing import Optional

from .models import CryptoPrimitive, Finding, QuantumRisk, Severity

REF_NIST_PQC = "https://csrc.nist.gov/projects/post-quantum-cryptography"
REF_RFC7296 = "https://www.rfc-editor.org/rfc/rfc7296"

# IKEv2 payload types
_PL_SA, _PL_KE, _PL_NONCE, _PL_NOTIFY = 33, 34, 40, 41
# Transform types
_T_ENCR, _T_PRF, _T_INTEG, _T_DH, _T_ESN = 1, 2, 3, 4, 5
_EXCH_SA_INIT = 34
_ATTR_KEYLEN = 0x800E          # AF=1, type 14 (key length)
_NOTIFY_INVALID_KE = 17
_NOTIFY_NO_PROPOSAL = 14

QV, BN, PQ, WK = (QuantumRisk.QUANTUM_VULNERABLE, QuantumRisk.BROKEN_NOW,
                  QuantumRisk.PQ_SAFE, QuantumRisk.QUANTUM_WEAKENED)

# Transform ID -> (name, base quantum risk). Key length refines symmetric risk.
# IDs per the IANA IKEv2 Transform Type 1 (Encryption) registry.
_ENCR = {2: ("DES", BN), 3: ("3DES", BN), 11: ("NULL", BN),
         12: ("AES-CBC", WK), 13: ("AES-CTR", WK),
         14: ("AES-CCM-8", WK), 15: ("AES-CCM-12", WK), 16: ("AES-CCM-16", WK),
         18: ("AES-GCM-8", WK), 19: ("AES-GCM-12", WK), 20: ("AES-GCM-16", WK),
         23: ("Camellia-CBC", WK), 28: ("ChaCha20-Poly1305", PQ)}
_PRF = {1: ("HMAC-MD5", BN), 2: ("HMAC-SHA1", BN), 5: ("HMAC-SHA2-256", PQ),
        6: ("HMAC-SHA2-384", PQ), 7: ("HMAC-SHA2-512", PQ)}
_INTEG = {1: ("HMAC-MD5-96", BN), 2: ("HMAC-SHA1-96", BN), 5: ("AES-XCBC-96", PQ),
          12: ("HMAC-SHA2-256-128", PQ), 13: ("HMAC-SHA2-384-192", PQ),
          14: ("HMAC-SHA2-512-256", PQ)}
# Transform Type 4 (Key Exchange Method). All classical (EC)DH groups are
# Shor-breakable (QV); the RFC 5114 MODP-1024 subgroup (22) is also legacy-weak;
# the standardised ML-KEM key-exchange methods (35-37) are PQ-safe.
_DH = {1: ("MODP-768", BN), 2: ("MODP-1024", BN), 5: ("MODP-1536", QV),
       14: ("MODP-2048", QV), 15: ("MODP-3072", QV), 16: ("MODP-4096", QV),
       17: ("MODP-6144", QV), 18: ("MODP-8192", QV), 19: ("ECP-256", QV),
       20: ("ECP-384", QV), 21: ("ECP-521", QV),
       22: ("MODP-1024-160", BN), 23: ("MODP-2048-224", QV), 24: ("MODP-2048-256", QV),
       27: ("brainpoolP224r1", QV), 28: ("brainpoolP256r1", QV),
       29: ("brainpoolP384r1", QV), 30: ("brainpoolP512r1", QV),
       31: ("Curve25519", QV), 32: ("Curve448", QV),
       33: ("GOST3410-2012-256", QV), 34: ("GOST3410-2012-512", QV),
       35: ("ML-KEM-512", PQ), 36: ("ML-KEM-768", PQ), 37: ("ML-KEM-1024", PQ)}
_TTYPE = {_T_ENCR: ("encryption", _ENCR), _T_PRF: ("prf", _PRF),
          _T_INTEG: ("integrity", _INTEG), _T_DH: ("dh-group", _DH)}


@dataclass
class IkeResult:
    host: str
    port: int
    reachable: bool = False
    error: Optional[str] = None
    responder: bool = False
    ike_version: Optional[str] = None
    chosen: dict = field(default_factory=dict)     # role -> {"id","name","keylen","quantum_risk"}
    invalid_ke_group: Optional[int] = None
    notifies: list = field(default_factory=list)
    primitives: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    raw_response_hex: Optional[str] = None        # the gateway's raw bytes (validation evidence)


# --------------------------------------------------------------------------- #
# Packet construction (IKE_SA_INIT request)
# --------------------------------------------------------------------------- #

def _keylen_attr(bits: int) -> bytes:
    return struct.pack("!HH", _ATTR_KEYLEN, bits)


def _transform(is_last: bool, ttype: int, tid: int, attrs: bytes = b"") -> bytes:
    inner = struct.pack("!BBH", ttype, 0, tid) + attrs        # type, reserved, id, attrs
    return struct.pack("!BBH", 0 if is_last else 3, 0, 4 + len(inner)) + inner


def _payload(next_payload: int, body: bytes) -> bytes:
    return struct.pack("!BBH", next_payload, 0, 4 + len(body)) + body


def _proposal(num: int, transforms: list, is_last: bool = True) -> bytes:
    body = b"".join(transforms)
    head = struct.pack("!BBHBBBB", 0 if is_last else 2, 0, 8 + len(body), num, 1, 0, len(transforms))
    return head + body                                         # protocol_id=1 (IKE), spi_size=0


def build_sa_init(initiator_spi: Optional[bytes] = None) -> bytes:
    init_spi = initiator_spi or os.urandom(8)
    transforms = [
        _transform(False, _T_ENCR, 20, _keylen_attr(256)),    # AES-GCM-16 256
        _transform(False, _T_ENCR, 12, _keylen_attr(256)),    # AES-CBC 256
        _transform(False, _T_ENCR, 12, _keylen_attr(128)),    # AES-CBC 128
        _transform(False, _T_ENCR, 3),                        # 3DES
        _transform(False, _T_PRF, 5), _transform(False, _T_PRF, 6), _transform(False, _T_PRF, 2),
        _transform(False, _T_INTEG, 12), _transform(False, _T_INTEG, 13), _transform(False, _T_INTEG, 2),
        _transform(False, _T_DH, 14), _transform(False, _T_DH, 19), _transform(False, _T_DH, 20),
        _transform(False, _T_DH, 21), _transform(True, _T_DH, 2),   # last
    ]
    sa = _payload(_PL_KE, _proposal(1, transforms))
    ke = _payload(_PL_NONCE, struct.pack("!HH", 14, 0) + os.urandom(256))   # KE for MODP-2048
    nonce = _payload(0, os.urandom(32))
    payloads = sa + ke + nonce
    header = (init_spi + b"\x00" * 8 + bytes([_PL_SA, 0x20, _EXCH_SA_INIT, 0x08])
              + struct.pack("!II", 0, 28 + len(payloads)))
    return header + payloads


# --------------------------------------------------------------------------- #
# Response parsing
# --------------------------------------------------------------------------- #

def _parse_sa(body: bytes, chosen: dict) -> None:
    if len(body) < 8:
        return
    _, _, _, _, _, spi_size, n_trans = struct.unpack("!BBHBBBB", body[:8])
    pos = 8 + spi_size
    for _ in range(n_trans):
        if pos + 8 > len(body):
            break
        t_last, _, t_len, ttype, _, tid = struct.unpack("!BBHBBH", body[pos:pos + 8])
        if t_len < 8 or pos + t_len > len(body):
            break
        attrs = body[pos + 8:pos + t_len]
        keylen = None
        if len(attrs) >= 4:
            at, av = struct.unpack("!HH", attrs[:4])
            if at == _ATTR_KEYLEN:
                keylen = av
        if ttype in _TTYPE:
            role, table = _TTYPE[ttype]
            name, _risk = table.get(tid, (f"unknown({tid})", QV))
            chosen[role] = {"id": tid, "name": name, "keylen": keylen}
        pos += t_len


def _parse_notify(body: bytes, result: IkeResult) -> None:
    if len(body) < 4:
        return
    _, spi_size, msg_type = struct.unpack("!BBH", body[:4])
    result.notifies.append(msg_type)
    data = body[4 + spi_size:]
    if msg_type == _NOTIFY_INVALID_KE and len(data) >= 2:
        result.invalid_ke_group = struct.unpack("!H", data[:2])[0]


def parse_response(data: bytes, host: str = "", port: int = 500) -> IkeResult:
    result = IkeResult(host=host, port=port)
    if len(data) < 28:
        result.error = "short IKE response"
        return result
    next_payload, version, exch_type, flags = data[16], data[17], data[18], data[19]
    result.reachable = True
    result.responder = bool(flags & 0x20)
    result.ike_version = f"{version >> 4}.{version & 0x0F}"
    pos, np = 28, next_payload
    while np != 0 and pos + 4 <= len(data):
        p_next, _crit, p_len = struct.unpack("!BBH", data[pos:pos + 4])
        if p_len < 4 or pos + p_len > len(data):
            break
        body = data[pos + 4:pos + p_len]
        if np == _PL_SA:
            _parse_sa(body, result.chosen)
        elif np == _PL_NOTIFY:
            _parse_notify(body, result)
        np = p_next
        pos += p_len
    return result


# --------------------------------------------------------------------------- #
# Classification + findings
# --------------------------------------------------------------------------- #

def _encr_risk(tid: int, keylen: Optional[int]) -> QuantumRisk:
    name, base = _ENCR.get(tid, (f"unknown({tid})", WK))
    if base in (BN, PQ):
        return base
    return PQ if (keylen and keylen >= 256) else WK     # 128-bit symmetric -> weakened


def classify(result: IkeResult) -> None:
    for role, info in result.chosen.items():
        tid, keylen = info["id"], info.get("keylen")
        if role == "encryption":
            risk = _encr_risk(tid, keylen)
        elif role == "dh-group":
            risk = _DH.get(tid, ("", QV))[1]
        elif role == "prf":
            risk = _PRF.get(tid, ("", PQ))[1]
        else:
            risk = _INTEG.get(tid, ("", PQ))[1]
        info["quantum_risk"] = risk.label
        algo = info["name"] + (f"-{keylen}" if keylen else "")
        result.primitives.append(CryptoPrimitive(
            role={"dh-group": "key-exchange", "encryption": "cipher",
                  "integrity": "mac", "prf": "prf"}.get(role, role),
            algorithm=algo, quantum_risk=risk))


def generate_ike_findings(result: IkeResult) -> list:
    host, port = result.host, result.port
    out: list[Finding] = []
    if not result.reachable:
        out.append(Finding(id="QER-IKE-UNREACHABLE", title="No IKE response",
            severity=Severity.INFO, quantum_risk=QuantumRisk.PQ_SAFE, category="inventory",
            host=host, port=port, description=result.error or "no IKE_SA_INIT response",
            recommendation="Confirm the gateway speaks IKEv2 on this UDP port."))
        return out

    dh = result.chosen.get("dh-group")
    if dh and _DH.get(dh["id"], ("", QV))[1] == PQ:
        # A post-quantum key-exchange method (ML-KEM, RFC 9370) — report it as good.
        out.append(Finding(id="QER-IKE-PQ-OK",
            title=f"Post-quantum IKE key exchange negotiated ({dh['name']})",
            severity=Severity.INFO, quantum_risk=QuantumRisk.PQ_SAFE, category="inventory",
            host=host, port=port,
            description="The VPN gateway negotiates a post-quantum key-exchange method; IPsec tunnels "
                        "are not harvest-now-decrypt-later exposed on key exchange.",
            evidence=f"DH group {dh['id']} = {dh['name']}",
            recommendation="Confirm the PQ method is a vetted implementation and enforced fleet-wide.",
            references=[REF_NIST_PQC]))
    elif dh:
        risk = _DH.get(dh["id"], ("", QV))[1]
        sev = Severity.HIGH if risk == BN else Severity.MEDIUM
        out.append(Finding(id="QER-IKE-DH",
            title=f"Quantum-vulnerable IKE key exchange ({dh['name']})",
            severity=sev, quantum_risk=risk, category="hndl", host=host, port=port,
            description="The VPN gateway negotiates classical Diffie-Hellman/ECDH key exchange, which "
                        "Shor's algorithm breaks. Recorded IPsec tunnels are harvest-now-decrypt-later "
                        "exposed; VPN traffic is typically long-lived and sensitive.",
            evidence=f"DH group {dh['id']} = {dh['name']}",
            recommendation="Adopt IKEv2 post-quantum key exchange (RFC 9370 additional key exchanges, "
                           "e.g. ML-KEM) as vendors ship it.",
            references=[REF_NIST_PQC, REF_RFC7296]))
    elif result.invalid_ke_group is not None:
        g = result.invalid_ke_group
        out.append(Finding(id="QER-IKE-DH",
            title=f"VPN gateway requires DH group {g} ({_DH.get(g, ('unknown', QV))[0]})",
            severity=Severity.MEDIUM, quantum_risk=_DH.get(g, ("", QV))[1], category="hndl",
            host=host, port=port,
            description="The gateway rejected the offered key share and requested a specific (classical, "
                        "quantum-vulnerable) Diffie-Hellman group via INVALID_KE_PAYLOAD.",
            evidence=f"INVALID_KE_PAYLOAD requested group {g}",
            recommendation="Plan PQ key exchange (RFC 9370).", references=[REF_NIST_PQC]))

    for role, info in result.chosen.items():
        rl = info.get("quantum_risk")
        if rl == "broken-now":
            out.append(Finding(id="QER-IKE-WEAK",
                title=f"Broken IKE/IPsec algorithm ({info['name']})",
                severity=Severity.HIGH, quantum_risk=BN, category="deprecated", host=host, port=port,
                description=f"The gateway negotiated a broken/legacy {role} transform.",
                evidence=f"{role}={info['name']} (id {info['id']})",
                recommendation="Disable legacy transforms (3DES, MODP-1024/768, SHA-1, MD5)."))
    return out


def scan_ike(host: str, port: int = 500, timeout: float = 5.0,
             initiator_spi: Optional[bytes] = None) -> IkeResult:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(build_sa_init(initiator_spi), (host, port))
        data, _addr = sock.recvfrom(4096)
    except socket.timeout:
        return IkeResult(host=host, port=port, reachable=False, error="timeout (no IKE response)")
    except OSError as exc:
        return IkeResult(host=host, port=port, reachable=False, error=f"{type(exc).__name__}: {exc}")
    finally:
        sock.close()

    result = parse_response(data, host, port)
    result.raw_response_hex = data.hex()
    classify(result)
    result.findings = generate_ike_findings(result)
    return result
