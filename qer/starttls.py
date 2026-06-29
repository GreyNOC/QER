"""Opportunistic-TLS (STARTTLS) negotiation for non-HTTPS services.

A huge amount of an enterprise's TLS — and therefore its quantum exposure — is
*not* on port 443. Mail (SMTP/IMAP/POP3), directory (LDAP), and databases
(PostgreSQL/MySQL) start in cleartext and *upgrade* to TLS via a protocol-specific
handshake. QER's TLS engine (the stdlib handshake, the version enumerator, the
raw PQ probe, and the raw certificate-chain probe) all work on a connected
socket, so this module's job is narrow and reusable: given a freshly connected
**plaintext** socket, perform the service's STARTTLS dance and return with the
socket positioned exactly where a TLS ClientHello should go. Every QER probe then
runs unchanged — including post-quantum detection over STARTTLS, which is the
point: "is my mail server PQ-ready?" was previously unanswerable.

``negotiate`` raises :class:`StartTLSError` on any failure so callers can report
a clean reason instead of a confusing TLS error.
"""

from __future__ import annotations

import socket
import struct
import time
from typing import Optional

# port -> default STARTTLS dialect. Implicit-TLS ports (465/993/995/636/3269)
# are deliberately absent: those speak TLS immediately, no negotiation needed.
STARTTLS_PORTS: dict[int, str] = {
    25: "smtp", 587: "smtp", 2525: "smtp",
    143: "imap",
    110: "pop3",
    389: "ldap", 3268: "ldap",
    5432: "postgres",
    3306: "mysql",
}

DIALECTS = {"smtp", "imap", "pop3", "ldap", "postgres", "mysql"}
_DISABLE = {"", "none", "off", "no", "false", "direct"}


class StartTLSError(Exception):
    """A STARTTLS negotiation failed before TLS could begin."""


def infer_dialect(port: int) -> Optional[str]:
    return STARTTLS_PORTS.get(port)


def resolve_dialect(explicit: Optional[str], port: int) -> Optional[str]:
    """Decide the effective STARTTLS dialect.

    * an explicit value wins (``"none"`` forces direct TLS even on a mail port);
    * otherwise infer from the port (so ``qer scan smtp.example.com:587`` just
      works). Unknown explicit dialects raise so typos aren't silently ignored.
    """
    if explicit is not None:
        e = explicit.strip().lower()
        if e in _DISABLE:
            return None
        if e in DIALECTS:
            return e
        raise StartTLSError(f"unknown STARTTLS dialect '{explicit}' "
                            f"(choose from {', '.join(sorted(DIALECTS))} or none)")
    return STARTTLS_PORTS.get(port)


# --------------------------------------------------------------------------- #
# A minimal buffered, deadline-bounded reader over the raw socket.
# --------------------------------------------------------------------------- #

class _Net:
    def __init__(self, sock: socket.socket, deadline: float):
        self.sock = sock
        self.deadline = deadline
        self.buf = bytearray()

    def _fill(self, hint: int = 1024) -> None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise StartTLSError("STARTTLS timed out")
        self.sock.settimeout(remaining)
        try:
            chunk = self.sock.recv(max(hint, 512))
        except (socket.timeout, OSError) as exc:
            raise StartTLSError(f"read failed: {exc}") from exc
        if not chunk:
            raise StartTLSError("connection closed during STARTTLS")
        self.buf += chunk

    def read_line(self, maxlen: int = 8192) -> str:
        while True:
            nl = self.buf.find(b"\n")
            if nl >= 0:
                line = bytes(self.buf[:nl]).rstrip(b"\r")
                del self.buf[:nl + 1]
                return line.decode("latin-1", "replace")
            if len(self.buf) > maxlen:
                raise StartTLSError("STARTTLS response line too long")
            self._fill()

    def read_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            self._fill(n - len(self.buf))
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def send(self, data: bytes) -> None:
        try:
            self.sock.sendall(data)
        except OSError as exc:
            raise StartTLSError(f"send failed: {exc}") from exc


# --------------------------------------------------------------------------- #
# Text protocols
# --------------------------------------------------------------------------- #

def _read_multiline_smtp(net: _Net) -> list[str]:
    """SMTP replies are ``NNN-...`` continuation lines then a final ``NNN ...``."""
    lines = []
    while True:
        line = net.read_line()
        lines.append(line)
        # a code is 3 digits; '-' after it means more lines follow, ' ' means last
        if len(line) < 4 or line[3] != "-":
            break
    return lines


def _ehlo_keyword(line: str) -> str:
    """The extension keyword from an EHLO reply line: '250-SIZE 1000' -> 'SIZE'.
    Matching the keyword exactly (not a substring) avoids a false positive when a
    hostname or parameter merely contains the text 'STARTTLS'."""
    body = line[4:].split() if len(line) > 4 else []
    return body[0].upper() if body else ""


def _negotiate_smtp(net: _Net, host: str) -> None:
    greeting = _read_multiline_smtp(net)
    if not greeting or not greeting[-1].startswith("220"):
        raise StartTLSError(f"unexpected SMTP greeting: {greeting[:1]}")
    net.send(b"EHLO qer.scan\r\n")
    ehlo = _read_multiline_smtp(net)
    if not ehlo or not ehlo[-1].startswith("250"):
        raise StartTLSError("SMTP EHLO refused")
    if "STARTTLS" not in {_ehlo_keyword(ln) for ln in ehlo}:
        raise StartTLSError("server does not advertise STARTTLS")
    net.send(b"STARTTLS\r\n")
    resp = net.read_line()
    if not resp.startswith("220"):
        raise StartTLSError(f"STARTTLS refused: {resp}")


def _negotiate_imap(net: _Net) -> None:
    greeting = net.read_line()
    if "OK" not in greeting.upper():
        raise StartTLSError(f"unexpected IMAP greeting: {greeting}")
    net.send(b"A1 STARTTLS\r\n")
    while True:
        line = net.read_line()
        if line.upper().startswith("A1 ") or line.upper().startswith("* BAD"):
            if line.upper().startswith("A1 OK"):
                return
            raise StartTLSError(f"IMAP STARTTLS refused: {line}")
        # untagged "*" lines may precede the tagged response; keep reading


def _negotiate_pop3(net: _Net) -> None:
    greeting = net.read_line()
    if not greeting.startswith("+OK"):
        raise StartTLSError(f"unexpected POP3 greeting: {greeting}")
    net.send(b"STLS\r\n")
    resp = net.read_line()
    if not resp.startswith("+OK"):
        raise StartTLSError(f"POP3 STLS refused: {resp}")


# --------------------------------------------------------------------------- #
# Binary protocols
# --------------------------------------------------------------------------- #

_LDAP_STARTTLS_OID = b"1.3.6.1.4.1.1466.20037"


def _negotiate_ldap(net: _Net) -> None:
    # LDAP ExtendedRequest (RFC 4511 §4.12) carrying the StartTLS OID as a
    # context-[0] ASCII string. messageID = 1.
    name = b"\x80" + bytes([len(_LDAP_STARTTLS_OID)]) + _LDAP_STARTTLS_OID
    ext_req = b"\x77" + bytes([len(name)]) + name          # [APPLICATION 23]
    msg_id = b"\x02\x01\x01"                                 # INTEGER 1
    body = msg_id + ext_req
    net.send(b"\x30" + bytes([len(body)]) + body)           # SEQUENCE

    if net.read_exact(1) != b"\x30":
        raise StartTLSError("LDAP response was not a SEQUENCE")
    seq_len = _read_ber_len(net)
    resp = net.read_exact(seq_len)
    # resp = INTEGER messageID, then [APPLICATION 24] ExtendedResponse whose
    # first field is ENUMERATED resultCode. Find "\x0a\x01\xNN" (resultCode).
    idx = resp.find(b"\x0a\x01")
    if idx < 0 or idx + 2 >= len(resp):
        raise StartTLSError("could not parse LDAP ExtendedResponse")
    if resp[idx + 2] != 0:
        raise StartTLSError(f"LDAP StartTLS resultCode {resp[idx + 2]}")


def _read_ber_len(net: _Net) -> int:
    first = net.read_exact(1)[0]
    if first < 0x80:
        return first
    nbytes = first & 0x7F
    if nbytes == 0 or nbytes > 4:
        raise StartTLSError("unsupported BER length")
    return int.from_bytes(net.read_exact(nbytes), "big")


def _negotiate_postgres(net: _Net) -> None:
    # PostgreSQL SSLRequest (protocol §55.2.10): int32 length=8, int32 code.
    net.send(struct.pack("!II", 8, 80877103))
    resp = net.read_exact(1)
    if resp == b"S":
        return                                              # server will speak TLS
    if resp == b"N":
        raise StartTLSError("PostgreSQL server has SSL disabled")
    raise StartTLSError(f"unexpected PostgreSQL SSL response: {resp!r}")


# MySQL client capability flags (subset).
_MYSQL_CLIENT_LONG_PASSWORD = 0x00000001
_MYSQL_CLIENT_PROTOCOL_41 = 0x00000200
_MYSQL_CLIENT_SSL = 0x00000800
_MYSQL_CLIENT_SECURE_CONNECTION = 0x00008000


def _mysql_server_supports_ssl(payload: bytes) -> bool:
    """Parse capability_flags (lower 16 bits) from a HandshakeV10 payload and
    test CLIENT_SSL. Layout: protocol(1) + server_version(NUL-terminated) +
    thread_id(4) + auth_plugin_data_1(8) + filler(1) + capability_flags_lower(2).
    Lenient (returns True) if the layout can't be parsed."""
    nul = payload.find(b"\x00", 1)
    if nul < 0:
        return True
    pos = nul + 1 + 4 + 8 + 1
    if pos + 2 > len(payload):
        return True
    cap_lower = int.from_bytes(payload[pos:pos + 2], "little")
    return bool(cap_lower & _MYSQL_CLIENT_SSL)


def _negotiate_mysql(net: _Net) -> None:
    # Read the server's initial handshake packet: 3-byte LE length + 1-byte seq.
    header = net.read_exact(4)
    plen = int.from_bytes(header[:3], "little")
    seq = header[3]
    payload = net.read_exact(plen)
    if payload[:1] == b"\xff":                              # ERR packet
        raise StartTLSError("MySQL refused the connection (ERR packet)")
    if not _mysql_server_supports_ssl(payload):            # mirror the postgres 'N' path
        raise StartTLSError("MySQL server has SSL disabled")

    caps = (_MYSQL_CLIENT_LONG_PASSWORD | _MYSQL_CLIENT_PROTOCOL_41
            | _MYSQL_CLIENT_SSL | _MYSQL_CLIENT_SECURE_CONNECTION)
    ssl_request = (struct.pack("<I", caps)                  # client capabilities
                   + struct.pack("<I", 16 * 1024 * 1024)    # max packet size
                   + bytes([45])                            # charset utf8mb4
                   + b"\x00" * 23)                          # reserved
    out_header = (len(ssl_request)).to_bytes(3, "little") + bytes([(seq + 1) & 0xFF])
    net.send(out_header + ssl_request)


_DISPATCH = {
    "imap": lambda net, host: _negotiate_imap(net),
    "pop3": lambda net, host: _negotiate_pop3(net),
    "ldap": lambda net, host: _negotiate_ldap(net),
    "postgres": lambda net, host: _negotiate_postgres(net),
    "mysql": lambda net, host: _negotiate_mysql(net),
    "smtp": lambda net, host: _negotiate_smtp(net, host),
}


def negotiate(sock: socket.socket, dialect: str, host: str = "",
              timeout: float = 6.0) -> None:
    """Perform STARTTLS on a connected plaintext ``sock``. On return the socket
    is ready for a TLS ClientHello. Raises :class:`StartTLSError` on failure."""
    fn = _DISPATCH.get(dialect)
    if fn is None:
        raise StartTLSError(f"unknown STARTTLS dialect '{dialect}'")
    net = _Net(sock, time.monotonic() + timeout)
    fn(net, host)
