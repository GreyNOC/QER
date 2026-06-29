"""Full certificate-chain capture via a raw TLS 1.2 handshake.

Python's stdlib ``ssl`` exposes only the *leaf* certificate on 3.11, so the
scanner could not inventory intermediate / root CAs — a real gap for a
cryptographic bill of materials, since a SHA-1-signed or RSA-1024 intermediate
is just as quantum/classically relevant as the leaf.

This module performs a raw TLS 1.2 ClientHello (deliberately *omitting* the
supported_versions extension so the server negotiates TLS 1.2 rather than 1.3),
because in TLS 1.2 the server's ``Certificate`` handshake message — which carries
the full ``certificate_list`` — is sent in **plaintext** before the handshake is
encrypted. We read just far enough to capture and parse it, then close.

TLS 1.3-only servers encrypt the Certificate message, so the chain cannot be
captured this way; the caller falls back to the stdlib leaf in that case.
No new dependencies; reuses the byte helpers from :mod:`qer.pqprobe`.
"""

from __future__ import annotations

import os
import socket
import struct
import time
from typing import Optional

from .pqprobe import _ext, _is_ip, _read_record

# Broad TLS 1.2 cipher set (ECDHE + RSA, GCM/CBC/ChaCha) + the renegotiation
# SCSV (0x00FF) so picky servers complete the hello. Any non-anon suite makes
# the server send its Certificate, which is all we need.
_TLS12_CIPHERS = [
    0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
    0x009C, 0x009D, 0x002F, 0x0035, 0x00FF,
]
_GROUPS = [0x001D, 0x0017, 0x0018]          # x25519, secp256r1, secp384r1
_SIG_ALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0601, 0x0201, 0x0203]

# Handshake message types
_HS_CERTIFICATE = 0x0B
_HS_SERVER_HELLO_DONE = 0x0E


def build_tls12_client_hello(server_name: str) -> bytes:
    """A TLS 1.2 ClientHello with NO supported_versions extension, so a dual
    TLS1.2/1.3 server negotiates 1.2 and sends its Certificate in plaintext."""
    random = os.urandom(32)
    session_block = b"\x00"                  # empty legacy_session_id

    cs = b"".join(struct.pack("!H", c) for c in _TLS12_CIPHERS)
    cs_block = struct.pack("!H", len(cs)) + cs
    compression = b"\x01\x00"

    ext = b""
    if server_name and not _is_ip(server_name):
        name = (server_name.encode("idna")
                if any(ord(c) > 127 for c in server_name) else server_name.encode())
        sni = struct.pack("!H", len(name) + 3) + b"\x00" + struct.pack("!H", len(name)) + name
        ext += _ext(0x0000, sni)
    sg = b"".join(struct.pack("!H", g) for g in _GROUPS)
    ext += _ext(0x000A, struct.pack("!H", len(sg)) + sg)      # supported_groups
    ext += _ext(0x000B, b"\x01\x00")                          # ec_point_formats: uncompressed
    sa = b"".join(struct.pack("!H", s) for s in _SIG_ALGS)
    ext += _ext(0x000D, struct.pack("!H", len(sa)) + sa)      # signature_algorithms

    ext_block = struct.pack("!H", len(ext)) + ext
    body = b"\x03\x03" + random + session_block + cs_block + compression + ext_block
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body   # ClientHello
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _parse_certificate_message(body: bytes) -> list[bytes]:
    """Parse a TLS Certificate message body into a list of DER certificates."""
    if len(body) < 3:
        return []
    total = int.from_bytes(body[0:3], "big")
    pos = 3
    end = min(3 + total, len(body))
    certs: list[bytes] = []
    while pos + 3 <= end:
        clen = int.from_bytes(body[pos:pos + 3], "big")
        pos += 3
        if clen == 0 or pos + clen > end:
            break
        certs.append(body[pos:pos + clen])
        pos += clen
    return certs


def _try_extract_certificate(hs: bytes) -> Optional[list[bytes]]:
    """Walk reassembled handshake bytes. Returns the cert list once the
    Certificate message is fully present, [] if ServerHelloDone arrives first,
    or None if more bytes are still needed."""
    pos = 0
    while pos + 4 <= len(hs):
        mtype = hs[pos]
        mlen = int.from_bytes(hs[pos + 1:pos + 4], "big")
        if pos + 4 + mlen > len(hs):
            return None                       # message not fully received yet
        body = hs[pos + 4:pos + 4 + mlen]
        if mtype == _HS_CERTIFICATE:
            return _parse_certificate_message(body)
        if mtype == _HS_SERVER_HELLO_DONE:
            return []                          # no Certificate before SHD
        pos += 4 + mlen
    return None


def fetch_certificate_chain(host: str, port: int, timeout: float = 6.0,
                            max_bytes: int = 262144,
                            starttls: Optional[str] = None) -> list[bytes]:
    """Return the server's full DER certificate chain (leaf first), or [] if it
    could not be captured (e.g. a TLS 1.3-only server, or a connection error).

    Bounded by an absolute ``timeout`` deadline (so a slow-trickling peer can't
    hang the scan) and a ``max_bytes`` reassembly cap (so a flood of records that
    never completes a Certificate message can't exhaust memory). Records are read
    until the Certificate arrives — there is no fixed record count, so a server
    that fragments a large chain into many small records is still captured."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
    except OSError:
        return []
    deadline = time.monotonic() + timeout
    if starttls:
        try:
            from .starttls import negotiate
            negotiate(sock, starttls, host, max(0.1, deadline - time.monotonic()))
        except Exception:
            try:
                sock.close()
            except OSError:
                pass
            return []
    try:
        sock.sendall(build_tls12_client_hello(host))
        hs = b""
        while len(hs) < max_bytes and time.monotonic() < deadline:
            rec = _read_record(sock, deadline)
            if rec is None:
                break
            ctype, payload = rec
            if ctype == 0x15:                  # alert -> give up (e.g. TLS 1.3-only)
                break
            if ctype != 0x16:                  # skip change_cipher_spec etc.
                continue
            hs += payload
            certs = _try_extract_certificate(hs)
            if certs is not None:
                return certs
        return []
    except OSError:
        return []
    finally:
        try:
            sock.close()
        except OSError:
            pass
