"""Active post-quantum / hybrid key-exchange probe.

Python's stdlib ``ssl`` has no API to offer TLS key-exchange *groups*, so the
v0.1 scanner could not tell whether a server supports hybrid PQ key exchange.
This module fixes that without any new dependency and without needing a modern
OpenSSL, by speaking just enough TLS 1.3 by hand.

Technique (RFC 8446 §4.1.4):

1. Send a ClientHello whose ``supported_groups`` extension advertises **only**
   the target group (e.g. X25519MLKEM768) and whose ``key_share`` extension is
   **empty** — i.e. we offer the group but provide no key share for it.
2. A server that supports the group must answer with a **HelloRetryRequest**
   that selects it (it cannot proceed without a key share, so it asks for one).
   A server that does not support it sends a ``handshake_failure`` alert.

So an HRR selecting our group is positive proof of support, and we never need an
ML-KEM implementation locally — we deliberately never send a PQ key share.

This is a *support* probe (does the server offer PQ at all), which in practice
is what determines whether PQ-capable clients get PQ protection. It does not
decrypt or interfere with anything.
"""

from __future__ import annotations

import os
import socket
import ssl
import struct
import time
from typing import Optional

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import x25519
    _HAVE_X25519 = True
except Exception:  # pragma: no cover
    _HAVE_X25519 = False

# x25519 named group (used as the classical key_share in the preference probe).
X25519_GROUP = 0x001D

# IANA TLS Supported Groups codepoints for PQ / hybrid groups.
PQ_GROUPS: dict[str, int] = {
    "X25519MLKEM768": 0x11EC,
    "SecP256r1MLKEM768": 0x11EB,
    "SecP384r1MLKEM1024": 0x11ED,
    "X25519Kyber768Draft00": 0x6399,   # pre-standard draft, still seen in the wild
}
DEFAULT_PROBE_GROUPS = [
    "X25519MLKEM768",         # the standardised hybrid the major CDNs negotiate
    "SecP256r1MLKEM768",      # CNSA/enterprise-leaning stacks enable only the P-256 hybrid
    "X25519Kyber768Draft00",  # pre-standard draft, still seen in the wild
]

# A HelloRetryRequest is a ServerHello carrying this magic value in `random`
# (RFC 8446 §4.1.3: SHA-256 of "HelloRetryRequest").
_HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)
assert len(_HRR_RANDOM) == 32, "HRR magic random must be 32 bytes"

_TLS13_CIPHERS = [0x1301, 0x1302, 0x1303]
_SIG_ALGS = [0x0804, 0x0403, 0x0401, 0x0805, 0x0806, 0x0807, 0x0501, 0x0601]


def _ext(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data


def _is_ip(host: str) -> bool:
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, host)
            return True
        except OSError:
            continue
    return False


def _x25519_key_share() -> Optional[bytes]:
    """A fresh ephemeral X25519 public key (32 raw bytes) for use as a key_share."""
    if not _HAVE_X25519:
        return None
    priv = x25519.X25519PrivateKey.generate()
    return priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def build_client_hello(server_name: str, groups: list[int],
                       key_shares: Optional[dict] = None) -> bytes:
    """Build a TLS record wrapping a ClientHello that offers `groups`.

    With no ``key_shares`` the key_share extension is empty, forcing a
    HelloRetryRequest from a supporting server (the *support* probe). With a
    ``key_shares`` mapping {group_code: public_bytes}, those shares are offered
    so the server can complete without an HRR (the *preference* probe)."""
    legacy_version = b"\x03\x03"
    random = os.urandom(32)
    session_id = os.urandom(32)
    session_block = bytes([len(session_id)]) + session_id

    cs = b"".join(struct.pack("!H", c) for c in _TLS13_CIPHERS)
    cs_block = struct.pack("!H", len(cs)) + cs
    compression = b"\x01\x00"

    ext = b""
    ext += _ext(0x002B, b"\x02\x03\x04")                       # supported_versions: TLS 1.3
    sg = b"".join(struct.pack("!H", g) for g in groups)
    ext += _ext(0x000A, struct.pack("!H", len(sg)) + sg)       # supported_groups
    sa = b"".join(struct.pack("!H", s) for s in _SIG_ALGS)
    ext += _ext(0x000D, struct.pack("!H", len(sa)) + sa)       # signature_algorithms
    ks_entries = b""
    for grp, share in (key_shares or {}).items():
        ks_entries += struct.pack("!HH", grp, len(share)) + share
    ext += _ext(0x0033, struct.pack("!H", len(ks_entries)) + ks_entries)   # key_share
    if server_name and not _is_ip(server_name):
        name = server_name.encode("idna") if any(ord(c) > 127 for c in server_name) else server_name.encode()
        sni = struct.pack("!H", len(name) + 3) + b"\x00" + struct.pack("!H", len(name)) + name
        ext += _ext(0x0000, sni)                               # server_name

    ext_block = struct.pack("!H", len(ext)) + ext
    body = legacy_version + random + session_block + cs_block + compression + ext_block
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body   # ClientHello, 3-byte length
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _read_record(sock: socket.socket, deadline: Optional[float] = None
                 ) -> Optional[tuple[int, bytes]]:
    """Read one TLS record. Returns (content_type, payload) or None."""
    header = _recv_exact(sock, 5, deadline)
    if not header or len(header) < 5:
        return None
    content_type = header[0]
    length = struct.unpack("!H", header[3:5])[0]
    payload = _recv_exact(sock, length, deadline)
    if payload is None or len(payload) != length:   # reject truncated records
        return None
    return content_type, payload


def _recv_exact(sock: socket.socket, n: int, deadline: Optional[float] = None) -> Optional[bytes]:
    """Read exactly n bytes, or None. All-or-nothing: a connection that closes
    before n bytes arrive yields None (never a partial buffer), so callers can't
    mistake a truncated record for a complete one. When ``deadline`` (a
    ``time.monotonic`` value) is given, the per-recv socket timeout is shrunk to
    the remaining budget, so a slow-trickling peer cannot drag the read past it."""
    buf = b""
    while len(buf) < n:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                sock.settimeout(remaining)
            except OSError:
                pass
        try:
            chunk = sock.recv(n - len(buf))
        except (socket.timeout, OSError):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def _selected_group_from_server_hello(body: bytes) -> Optional[int]:
    """Parse a ServerHello/HRR handshake body and return the key_share /
    selected group codepoint, if present."""
    try:
        # handshake header: type(1) + len(3)
        if not body or body[0] != 0x02:
            return None
        msg = body[4:]
        pos = 2 + 32                                  # legacy_version + random
        sid_len = msg[pos]; pos += 1 + sid_len        # legacy_session_id_echo
        pos += 2 + 1                                  # cipher_suite + compression_method
        ext_total = struct.unpack("!H", msg[pos:pos + 2])[0]; pos += 2
        end = pos + ext_total
        while pos + 4 <= end:
            etype, elen = struct.unpack("!H", msg[pos:pos + 2])[0], struct.unpack("!H", msg[pos + 2:pos + 4])[0]
            pos += 4
            if pos + elen > end:                       # extension length lies beyond the block
                break
            edata = msg[pos:pos + elen]; pos += elen
            if etype == 0x0033 and len(edata) >= 2:    # key_share: HRR carries selected_group (2 bytes)
                return struct.unpack("!H", edata[:2])[0]
        return None
    except (IndexError, struct.error):
        return None


def _is_hello_retry(body: bytes) -> bool:
    return len(body) >= 6 + 32 and body[6:6 + 32] == _HRR_RANDOM


# Fatal alerts that reliably mean "the offered group was rejected". Other alerts
# (protocol_version from a TLS<=1.2 server, internal_error, warning-level, ...)
# say nothing about PQ support, so they are inconclusive (None), not a False.
_REJECT_ALERTS = {40, 71}   # handshake_failure, insufficient_security


def _alert_means_unsupported(payload: bytes) -> Optional[bool]:
    desc = payload[1] if len(payload) >= 2 else None
    return False if desc in _REJECT_ALERTS else None


def _open(host: str, port: int, timeout: float, starttls: Optional[str],
          deadline: Optional[float] = None):
    """Connect and (optionally) run STARTTLS; return a socket positioned for a
    raw ClientHello, or None on any failure. STARTTLS is bounded by ``deadline``
    so the whole probe stays within one ``timeout`` budget."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
    except OSError:
        return None
    if starttls:
        try:
            from .starttls import negotiate
            budget = max(0.1, deadline - time.monotonic()) if deadline else timeout
            negotiate(sock, starttls, host, budget)
        except Exception:
            try:
                sock.close()
            except OSError:
                pass
            return None
    return sock


def probe_group(host: str, port: int, group_name: str, timeout: float = 6.0,
                starttls: Optional[str] = None) -> Optional[bool]:
    """Probe a single group. True=supported, False=not supported, None=error."""
    group = PQ_GROUPS.get(group_name)
    if group is None:
        return None
    deadline = time.monotonic() + timeout
    sock = _open(host, port, timeout, starttls, deadline)
    if sock is None:
        return None
    try:
        sock.sendall(build_client_hello(host, [group]))
        for _ in range(4):                             # skip change_cipher_spec etc.
            rec = _read_record(sock, deadline)
            if rec is None:
                return None
            ctype, payload = rec
            if ctype == 0x15:                          # alert
                return _alert_means_unsupported(payload)
            if ctype == 0x16:                          # handshake (ServerHello / HRR)
                if _is_hello_retry(payload) or payload[:1] == b"\x02":
                    selected = _selected_group_from_server_hello(payload)
                    return selected == group
            # otherwise (e.g. 0x14 CCS) keep reading
        return None
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _interpret_preference(is_hrr: bool, selected_group: Optional[int],
                          target_group: int) -> str:
    """Pure decision rule for the preference probe (see ``probe_preference``).

    We offered [target_group, x25519] and a key_share for x25519 only:
    * HRR selecting target_group -> the server demanded PQ despite our usable
      x25519 share => it ``enforce``s PQ.
    * anything else (HRR for x25519, or a ServerHello that completed with our
      x25519 share) => it ``tolerate``s PQ but accepts classical."""
    if is_hrr and selected_group == target_group:
        return "enforce"
    return "tolerate"


def probe_preference(host: str, port: int, group_name: str,
                     timeout: float = 6.0, starttls: Optional[str] = None) -> Optional[str]:
    """Does the server *enforce* a hybrid group, or merely tolerate it?

    We offer ``[group, x25519]`` and provide a key_share **for x25519 only**,
    so the server could complete the handshake classically with zero extra
    round-trips. What it does reveals its group preference:

    * ``"enforce"``  — it sends a HelloRetryRequest demanding the hybrid group
      even though it could have finished with the x25519 share we provided. It
      actively upgrades PQ-advertising clients to PQ.
    * ``"tolerate"`` — it completes with x25519 (a normal ServerHello). It
      supports the hybrid group but accepts classical when the client offers it.
    * ``None`` on error / unable to test.
    """
    group = PQ_GROUPS.get(group_name)
    share = _x25519_key_share()
    if group is None or share is None:
        return None
    deadline = time.monotonic() + timeout
    sock = _open(host, port, timeout, starttls, deadline)
    if sock is None:
        return None
    try:
        sock.sendall(build_client_hello(host, [group, X25519_GROUP], {X25519_GROUP: share}))
        for _ in range(4):
            rec = _read_record(sock, deadline)
            if rec is None:
                return None
            ctype, payload = rec
            if ctype == 0x15:                          # alert
                return None
            if ctype == 0x16:                          # handshake
                if _is_hello_retry(payload):
                    return _interpret_preference(True, _selected_group_from_server_hello(payload), group)
                if payload[:1] == b"\x02":             # ServerHello -> completed with x25519
                    return _interpret_preference(False, None, group)
        return None
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe_pq(host: str, port: int, timeout: float = 6.0,
             groups: Optional[list[str]] = None, check_preference: bool = True,
             starttls: Optional[str] = None) -> dict:
    """Probe a set of PQ groups. Returns a result dict with the supported list,
    and (if any are supported and ``check_preference``) whether the server
    enforces PQ for the first supported group."""
    groups = groups or DEFAULT_PROBE_GROUPS
    supported: list[str] = []
    errored = 0
    for name in groups:
        result = probe_group(host, port, name, timeout, starttls=starttls)
        if result is True:
            supported.append(name)
        elif result is None:
            errored += 1

    preference = None
    pq_preferred = None
    if supported and check_preference:
        preference = probe_preference(host, port, supported[0], timeout, starttls=starttls)
        if preference == "enforce":
            pq_preferred = True
        elif preference == "tolerate":
            pq_preferred = False

    # If every probe errored (all groups unknown/typo'd, or the network RST/timed
    # out each raw connection) we have *no* evidence either way — don't report a
    # confident "no PQ support", which would let downgrade.py raise a false
    # CRITICAL PQ-downgrade alert against a baseline that saw PQ.
    testable = bool(supported) or errored < len(groups)
    return {
        "testable": testable,
        "tested_groups": groups,
        "supported_groups": supported,
        "pq_supported": bool(supported) if testable else None,
        "preference": preference,
        "pq_preferred": pq_preferred,
        "openssl": ssl.OPENSSL_VERSION,
        "errored": errored,
    }
