"""SSH transport-layer scanner for quantum-risk crypto inventory (RFC 4253).

SSH is one of the largest "harvest now, decrypt later" surfaces in any estate:
administrative sessions, git traffic, port-forwarded databases — all key-exchanged
with classical (EC)DH (Shor-vulnerable) and frequently long-lived. Yet almost no
inventory tooling classifies SSH for quantum risk.

This module speaks just enough of the SSH-2.0 transport protocol to take a full
attendance of what a server *offers*: it exchanges identification banners and
parses the server's ``SSH_MSG_KEXINIT`` — the message every SSH server sends
unprompted at the very start of a connection, carrying preference-ordered
name-lists of every key-exchange, host-key, cipher, MAC and compression
algorithm it supports. No authentication is attempted and the handshake is never
completed; we only read the offer, classify it, and disconnect.

The headline detection: modern OpenSSH (>= 9.0) *prefers* a post-quantum hybrid
key exchange (``sntrup761x25519-sha512@openssh.com``; ``mlkem768x25519-sha256``
in 9.9+). Because SSH name-lists are in preference order, QER can tell not just
whether PQ key exchange is *offered* but whether it is *preferred* — the SSH
analogue of the TLS enforce-vs-tolerate distinction.
"""

from __future__ import annotations

import re
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from .classify import is_pq_algorithm
from .models import CryptoPrimitive, Finding, QuantumRisk, Severity

REF_NIST_PQC = "https://csrc.nist.gov/projects/post-quantum-cryptography"
REF_RFC4253 = "https://www.rfc-editor.org/rfc/rfc4253"
REF_OPENSSH_PQ = "https://www.openssh.com/pq.html"

QV, BN, PQ, WK = (QuantumRisk.QUANTUM_VULNERABLE, QuantumRisk.BROKEN_NOW,
                  QuantumRisk.PQ_SAFE, QuantumRisk.QUANTUM_WEAKENED)

_MSG_KEXINIT = 20
_MAX_PACKET = 256 * 1024          # generous ceiling; a real KEXINIT is well under 4 KiB
_MAX_IDENT_BYTES = 64 * 1024      # bound pre-banner text a hostile server might dribble

# Name-list tokens that are protocol signalling, not real algorithms — never
# classify or count these (OpenSSH extension negotiation / strict-kex markers).
_SIGNALLING = {
    "ext-info-c", "ext-info-s",
    "kex-strict-c-v00@openssh.com", "kex-strict-s-v00@openssh.com",
}

# A self-described client banner. SSH requires the "SSH-2.0-" prefix; the rest is
# free-form software/comment text.
_CLIENT_IDENT = b"SSH-2.0-QER_scanner\r\n"


@dataclass
class SshResult:
    host: str
    port: int
    reachable: bool = False
    error: Optional[str] = None
    banner: Optional[str] = None              # server identification string
    software: Optional[str] = None            # the software-version field of the banner
    kex_algorithms: list = field(default_factory=list)
    host_key_algorithms: list = field(default_factory=list)
    ciphers: list = field(default_factory=list)        # server->client (== c2s in practice)
    macs: list = field(default_factory=list)
    compression: list = field(default_factory=list)
    preferred_kex: Optional[str] = None
    pq_kex_offered: bool = False
    pq_kex_preferred: bool = False
    primitives: list = field(default_factory=list)
    findings: list = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Wire I/O
#
# A single buffered reader is essential: a server may pack its identification
# line AND its binary KEXINIT into one TCP segment, so the banner reader MUST
# hand any bytes it over-read to the packet reader rather than discarding them.
# --------------------------------------------------------------------------- #

class _Reader:
    def __init__(self, sock: socket.socket, deadline: float):
        self.sock = sock
        self.deadline = deadline
        self.buf = bytearray()

    def _recv_more(self, hint: int = 512) -> None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("ssh read timed out")
        self.sock.settimeout(remaining)
        chunk = self.sock.recv(max(hint, 512))
        if not chunk:
            raise ConnectionError("connection closed by peer")
        self.buf += chunk

    def read_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            self._recv_more(n - len(self.buf))
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def read_ident_line(self) -> str:
        """Return the server ``SSH-`` identification line, skipping any preamble
        lines (RFC 4253 §4.2). Bytes after the line stay buffered for the packet
        reader."""
        while True:
            nl = self.buf.find(b"\n")
            if nl >= 0:
                line = bytes(self.buf[:nl]).rstrip(b"\r")
                del self.buf[:nl + 1]
                text = line.decode("latin-1", "replace")
                if text.startswith("SSH-"):
                    return text
                continue                   # a pre-banner line; keep scanning
            if len(self.buf) > _MAX_IDENT_BYTES:
                raise ValueError("identification string too long")
            self._recv_more()


def _read_kexinit_payload(reader: _Reader) -> bytes:
    """Read SSH binary packets until a KEXINIT is found; return its payload.

    Pre-encryption packet framing (RFC 4253 §6): uint32 packet_length, then
    that many bytes = padding_length(1) + payload + random padding."""
    for _ in range(4):                     # tolerate a stray IGNORE/DEBUG packet
        packet_length = struct.unpack("!I", reader.read_exact(4))[0]
        if packet_length < 2 or packet_length > _MAX_PACKET:
            raise ValueError(f"implausible SSH packet length {packet_length}")
        body = reader.read_exact(packet_length)
        padding_length = body[0]
        if padding_length > packet_length - 1:
            raise ValueError("corrupt SSH packet padding")
        payload = body[1:packet_length - padding_length]
        if payload and payload[0] == _MSG_KEXINIT:
            return payload
    raise ValueError("no KEXINIT received")


# --------------------------------------------------------------------------- #
# KEXINIT parsing
# --------------------------------------------------------------------------- #

def _read_namelist(buf: bytes, pos: int) -> tuple[list[str], int]:
    if pos + 4 > len(buf):
        raise ValueError("truncated name-list length")
    (length,) = struct.unpack("!I", buf[pos:pos + 4])
    pos += 4
    if pos + length > len(buf):
        raise ValueError("truncated name-list body")
    raw = buf[pos:pos + length].decode("ascii", "replace")
    pos += length
    names = [n for n in raw.split(",") if n] if raw else []
    return names, pos


def parse_kexinit(payload: bytes) -> dict:
    """Parse a KEXINIT payload into its ten name-lists (RFC 4253 §7.1)."""
    # byte msg(20) + byte[16] cookie, then the name-lists.
    pos = 17
    fields = ("kex", "host_key", "enc_c2s", "enc_s2c", "mac_c2s", "mac_s2c",
              "comp_c2s", "comp_s2c", "lang_c2s", "lang_s2c")
    out: dict = {}
    for name in fields:
        out[name], pos = _read_namelist(payload, pos)
    return out


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #

def _is_real_kex(name: str) -> bool:
    return name not in _SIGNALLING and not name.startswith("kex-strict")


# "group1" as a whole token (the 1024-bit Oakley group 2), NOT a prefix of
# group14/15/16/18. The negative lookahead keeps modern groups out of "broken".
_WEAK_DH_GROUP = re.compile(r"group1(?![0-9])")


def classify_kex(name: str) -> tuple[QuantumRisk, str]:
    n = name.lower()
    if is_pq_algorithm(name):
        return PQ, "Post-quantum / hybrid SSH key exchange (Shor-resistant)."
    if "sha1" in n or "sha-1" in n or _WEAK_DH_GROUP.search(n):
        return BN, "Key exchange uses SHA-1 and/or a 1024-bit MODP group; broken today."
    if n.startswith("gss-"):
        return QV, "GSSAPI key exchange over a classical group; quantum-vulnerable."
    return QV, ("Classical (EC)DH key exchange, broken by Shor's algorithm — "
                "recorded SSH sessions are harvest-now-decrypt-later exposed.")


def classify_hostkey(name: str) -> tuple[QuantumRisk, str]:
    n = name.lower()
    if is_pq_algorithm(name):
        return PQ, "Post-quantum host-key signature."
    if n == "ssh-rsa" or n.startswith("ssh-rsa-cert") or "ssh-dss" in n:
        # ssh-rsa = RSA with a SHA-1 signature (RFC 8332); ssh-dss = DSA-1024.
        return BN, "Legacy host-key signature (SHA-1 RSA or DSA); deprecated."
    return QV, "Host-key signature is quantum-vulnerable (Shor) — drives future impersonation risk."


def classify_cipher(name: str) -> tuple[QuantumRisk, Optional[int], str]:
    n = name.lower()
    if n == "none":
        return BN, 0, "NULL cipher: no confidentiality."
    if "chacha20" in n:
        return PQ, 256, ""
    if "aes256" in n or "aes-256" in n:
        return PQ, 256, ""
    if "aes192" in n or "aes-192" in n:
        return PQ, 192, ""
    if "aes128" in n or "aes-128" in n:
        return WK, 128, "128-bit symmetric: ~64-bit post-Grover margin; prefer 256-bit for long-lived sessions."
    if "3des" in n:
        return BN, 112, "3DES is deprecated (SWEET32)."
    if "arcfour" in n or "rc4" in n:
        return BN, None, "RC4/arcfour is broken."
    if n.startswith("des-cbc") or n == "des":
        return BN, 56, "Single DES is broken."
    if "blowfish" in n or "cast128" in n or "idea" in n:
        return WK, 128, "Legacy 64/128-bit block cipher."
    return WK, None, "Unrecognised cipher; treated as weak."


def classify_mac(name: str) -> tuple[QuantumRisk, str]:
    n = name.lower()
    if "md5" in n:
        return BN, "HMAC-MD5 is obsolete."
    if "sha1" in n or "-sha-1" in n:
        return BN, "HMAC-SHA1 is legacy; retire."
    if "umac-64" in n:
        return WK, "64-bit UMAC tag is thin."
    if "sha2-256" in n or "sha256" in n or "sha2-512" in n or "sha512" in n or "umac-128" in n:
        return PQ, ""
    return WK, "Unrecognised MAC."


def classify(result: SshResult) -> None:
    """Populate quantum risks, the PQ-KEX verdict, and the CBOM primitives."""
    real_kex = [k for k in result.kex_algorithms if _is_real_kex(k)]
    result.preferred_kex = real_kex[0] if real_kex else None
    result.pq_kex_offered = any(is_pq_algorithm(k) for k in real_kex)
    result.pq_kex_preferred = bool(result.preferred_kex and is_pq_algorithm(result.preferred_kex))

    def _prim(role: str, name: Optional[str], risk: QuantumRisk, bits=None, note="") -> None:
        if not name:
            return
        result.primitives.append(CryptoPrimitive(
            role=role, algorithm=name, quantum_risk=risk, bits=bits, note=note))

    if result.preferred_kex:
        krisk, knote = classify_kex(result.preferred_kex)
        _prim("key-exchange", result.preferred_kex, krisk, note=knote)
    if result.host_key_algorithms:
        hk = result.host_key_algorithms[0]
        hrisk, hnote = classify_hostkey(hk)
        _prim("authentication", hk, hrisk, note=hnote)
    if result.ciphers:
        crisk, cbits, cnote = classify_cipher(result.ciphers[0])
        _prim("cipher", result.ciphers[0], crisk, bits=cbits, note=cnote)
    if result.macs:
        mrisk, mnote = classify_mac(result.macs[0])
        _prim("mac", result.macs[0], mrisk, note=mnote)


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #

def _broken_offerings(result: SshResult) -> list[str]:
    out: list[str] = []
    for k in result.kex_algorithms:
        if _is_real_kex(k) and classify_kex(k)[0] == BN:
            out.append(f"{k} (kex)")
    for hk in result.host_key_algorithms:
        if classify_hostkey(hk)[0] == BN:
            out.append(f"{hk} (host-key)")
    for c in result.ciphers:
        if classify_cipher(c)[0] == BN:
            out.append(f"{c} (cipher)")
    for m in result.macs:
        if classify_mac(m)[0] == BN:
            out.append(f"{m} (mac)")
    return out


def generate_ssh_findings(result: SshResult) -> list[Finding]:
    host, port = result.host, result.port
    out: list[Finding] = []
    if not result.reachable:
        out.append(Finding(
            id="QER-SSH-UNREACHABLE", title="No SSH identification received",
            severity=Severity.INFO, quantum_risk=QuantumRisk.PQ_SAFE, category="inventory",
            host=host, port=port, description=result.error or "no SSH banner / KEXINIT",
            recommendation="Confirm the host runs SSH on this port."))
        return out

    # --- key-exchange / HNDL verdict ---------------------------------------- #
    if result.pq_kex_preferred:
        out.append(Finding(
            id="QER-SSH-PQ-OK",
            title=f"SSH prefers post-quantum key exchange ({result.preferred_kex})",
            severity=Severity.INFO, quantum_risk=QuantumRisk.PQ_SAFE, category="pqc",
            host=host, port=port,
            description="The server lists a hybrid post-quantum key exchange first, so any PQ-capable "
                        "client negotiates a Shor-resistant handshake. This is the strong posture.",
            evidence=f"preferred kex={result.preferred_kex}; offered={', '.join(result.kex_algorithms)}",
            recommendation="Maintain; ensure clients are recent enough to negotiate the PQ group.",
            references=[REF_OPENSSH_PQ, REF_NIST_PQC]))
    elif result.pq_kex_offered:
        out.append(Finding(
            id="QER-SSH-PQ-PARTIAL",
            title="SSH offers post-quantum key exchange but does not prefer it",
            severity=Severity.LOW, quantum_risk=QuantumRisk.QUANTUM_VULNERABLE, category="hndl",
            host=host, port=port,
            description="A hybrid PQ key exchange is in the server's list but a classical group is preferred, "
                        "so clients commonly negotiate classical, Shor-breakable key exchange. Recorded "
                        "sessions remain harvest-now-decrypt-later exposed.",
            evidence=f"preferred={result.preferred_kex}; pq offered but not first",
            recommendation="Reorder KexAlgorithms to put the PQ hybrid first (sshd_config).",
            references=[REF_OPENSSH_PQ, REF_NIST_PQC]))
    else:
        krisk = classify_kex(result.preferred_kex)[0] if result.preferred_kex else QV
        out.append(Finding(
            id="QER-SSH-KEX-HNDL",
            title=f"Quantum-vulnerable SSH key exchange ({result.preferred_kex or 'unknown'})",
            severity=Severity.HIGH if krisk == BN else Severity.MEDIUM,
            quantum_risk=max(krisk, QV), category="hndl", host=host, port=port,
            description="The server offers no post-quantum key exchange; every SSH session is established "
                        "with classical (EC)DH that Shor's algorithm breaks. SSH carries admin access and "
                        "tunneled traffic that is high-value to harvest now and decrypt later.",
            evidence=f"kex offered: {', '.join(result.kex_algorithms) or '(none parsed)'}",
            recommendation="Upgrade to OpenSSH >= 9.0 and enable a hybrid group "
                           "(sntrup761x25519-sha512@openssh.com or mlkem768x25519-sha256).",
            references=[REF_OPENSSH_PQ, REF_NIST_PQC]))

    # --- broken / legacy algorithms ----------------------------------------- #
    broken = _broken_offerings(result)
    if broken:
        out.append(Finding(
            id="QER-SSH-WEAK", title=f"SSH offers broken/legacy algorithms ({len(broken)})",
            severity=Severity.HIGH, quantum_risk=QuantumRisk.BROKEN_NOW, category="deprecated",
            host=host, port=port,
            description="The server still offers algorithms that are broken or deprecated independent of "
                        "quantum concerns. A downgrade-capable or legacy client can select them.",
            evidence="; ".join(broken),
            recommendation="Remove SHA-1 kex, 3DES/RC4/DES ciphers, HMAC-MD5/SHA1, and ssh-rsa/ssh-dss host keys.",
            references=[REF_RFC4253]))

    # --- host-key (future impersonation) ------------------------------------ #
    qv_hostkeys = [hk for hk in result.host_key_algorithms
                   if classify_hostkey(hk)[0] >= QuantumRisk.QUANTUM_VULNERABLE]
    if qv_hostkeys:
        out.append(Finding(
            id="QER-SSH-HOSTKEY",
            title=f"Quantum-vulnerable SSH host keys ({', '.join(dict.fromkeys(qv_hostkeys))})",
            severity=Severity.MEDIUM, quantum_risk=QuantumRisk.QUANTUM_VULNERABLE, category="pqc",
            host=host, port=port,
            description="All offered host-key signature algorithms are RSA/ECDSA/EdDSA — broken by Shor. "
                        "This is not harvest-now (you cannot forge a past handshake) but it is the future "
                        "host-impersonation risk and the driver for PQ host-key migration.",
            evidence=f"host-key algorithms: {', '.join(result.host_key_algorithms)}",
            recommendation="Track OpenSSH support for PQ host-key signatures; plan rotation when shipped.",
            references=[REF_NIST_PQC]))

    # --- full inventory (CBOM) ---------------------------------------------- #
    out.append(Finding(
        id="QER-SSH-CBOM",
        title=f"SSH crypto inventory ({result.software or 'unknown server'})",
        severity=Severity.INFO,
        quantum_risk=max((p.quantum_risk for p in result.primitives), default=QuantumRisk.PQ_SAFE),
        category="inventory", host=host, port=port,
        description="Full set of cryptographic algorithms the SSH server offers, in preference order.",
        evidence=(f"kex=[{', '.join(result.kex_algorithms)}] "
                  f"hostkey=[{', '.join(result.host_key_algorithms)}] "
                  f"cipher=[{', '.join(result.ciphers)}] mac=[{', '.join(result.macs)}]"),
        recommendation="Inventory only; see other findings for actions.",
        references=[REF_RFC4253]))
    return out


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def scan_ssh(host: str, port: int = 22, timeout: float = 6.0) -> SshResult:
    result = SshResult(host=host, port=port)
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        return result
    # Start the read budget AFTER the (blocking) connect, so a slow connect
    # doesn't steal time from the banner/KEXINIT reads.
    deadline = time.monotonic() + timeout
    try:
        sock.sendall(_CLIENT_IDENT)
        reader = _Reader(sock, deadline)
        result.banner = reader.read_ident_line()
        # software-version is the field after "SSH-2.0-", up to the first space.
        ident_body = result.banner.split("-", 2)[2] if result.banner.count("-") >= 2 else ""
        result.software = ident_body.split(" ", 1)[0] or None
        payload = _read_kexinit_payload(reader)
    except (OSError, ValueError, TimeoutError) as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        result.reachable = bool(result.banner)
        return result
    finally:
        try:
            sock.close()
        except OSError:
            pass

    try:
        lists = parse_kexinit(payload)
    except ValueError as exc:
        result.error = f"KEXINIT parse failed: {exc}"
        result.reachable = True
        return result

    result.reachable = True
    result.kex_algorithms = lists["kex"]
    result.host_key_algorithms = lists["host_key"]
    result.ciphers = lists["enc_s2c"] or lists["enc_c2s"]
    result.macs = lists["mac_s2c"] or lists["mac_c2s"]
    result.compression = lists["comp_s2c"] or lists["comp_c2s"]
    classify(result)
    result.findings = generate_ssh_findings(result)
    return result
