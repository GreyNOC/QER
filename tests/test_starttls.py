"""Tests for STARTTLS negotiation (qer.starttls)."""

from __future__ import annotations

import struct

import pytest

from qer import starttls
from qer.starttls import StartTLSError, negotiate, resolve_dialect


class FakeSock:
    """Replays a scripted server byte stream and records what the client sends."""

    def __init__(self, script: bytes):
        self.script, self.pos, self.sent = script, 0, bytearray()

    def settimeout(self, _t):
        pass

    def recv(self, n):
        if self.pos >= len(self.script):
            return b""
        out = self.script[self.pos:self.pos + n]
        self.pos += len(out)
        return out

    def sendall(self, b):
        self.sent += b

    def close(self):
        pass


# --------------------------------------------------------------------------- #
# Dialect resolution
# --------------------------------------------------------------------------- #

def test_resolve_infers_from_port():
    assert resolve_dialect(None, 587) == "smtp"
    assert resolve_dialect(None, 143) == "imap"
    assert resolve_dialect(None, 5432) == "postgres"
    assert resolve_dialect(None, 443) is None          # not a STARTTLS port


def test_resolve_explicit_overrides_and_disables():
    assert resolve_dialect("smtp", 443) == "smtp"      # force on a non-mail port
    assert resolve_dialect("SMTP", 25) == "smtp"       # case-insensitive
    assert resolve_dialect("none", 587) is None        # force direct TLS on a mail port


def test_resolve_unknown_raises():
    with pytest.raises(StartTLSError):
        resolve_dialect("gopher", 70)


# --------------------------------------------------------------------------- #
# Text protocols
# --------------------------------------------------------------------------- #

def test_smtp_success():
    script = (b"220 mx.example.com ESMTP\r\n"
              b"250-mx.example.com\r\n250-PIPELINING\r\n250 STARTTLS\r\n"
              b"220 2.0.0 Ready to start TLS\r\n")
    sock = FakeSock(script)
    negotiate(sock, "smtp", "example.com", timeout=5)
    assert b"EHLO" in sock.sent and b"STARTTLS\r\n" in sock.sent


def test_smtp_without_starttls_capability_raises():
    script = (b"220 mx ESMTP\r\n"
              b"250-mx\r\n250 SIZE 1000\r\n")               # no STARTTLS advertised
    with pytest.raises(StartTLSError, match="STARTTLS"):
        negotiate(FakeSock(script), "smtp", "example.com", timeout=5)


def test_imap_success_with_preamble():
    script = b"* OK [CAPABILITY IMAP4rev1] ready\r\n* CAPABILITY IMAP4rev1\r\nA1 OK begin TLS\r\n"
    sock = FakeSock(script)
    negotiate(sock, "imap", "example.com", timeout=5)
    assert b"A1 STARTTLS\r\n" in sock.sent


def test_imap_refused_raises():
    script = b"* OK ready\r\nA1 NO STARTTLS not available\r\n"
    with pytest.raises(StartTLSError):
        negotiate(FakeSock(script), "imap", "example.com", timeout=5)


def test_pop3_success():
    sock = FakeSock(b"+OK POP3 ready\r\n+OK Begin TLS negotiation\r\n")
    negotiate(sock, "pop3", "example.com", timeout=5)
    assert b"STLS\r\n" in sock.sent


def test_pop3_refused_raises():
    with pytest.raises(StartTLSError):
        negotiate(FakeSock(b"+OK ready\r\n-ERR no STLS\r\n"), "pop3", "h", timeout=5)


# --------------------------------------------------------------------------- #
# Binary protocols
# --------------------------------------------------------------------------- #

def test_postgres_supported():
    sock = FakeSock(b"S")
    negotiate(sock, "postgres", "h", timeout=5)
    # client must have sent the 8-byte SSLRequest (length 8, code 80877103)
    assert sock.sent == struct.pack("!II", 8, 80877103)


def test_postgres_disabled_raises():
    with pytest.raises(StartTLSError, match="SSL disabled"):
        negotiate(FakeSock(b"N"), "postgres", "h", timeout=5)


def _ldap_response(result_code: int) -> bytes:
    body = bytes([0x0a, 0x01, result_code]) + b"\x04\x00" + b"\x04\x00"
    ext = b"\x78" + bytes([len(body)]) + body
    contents = b"\x02\x01\x01" + ext
    return b"\x30" + bytes([len(contents)]) + contents


def test_ldap_success():
    sock = FakeSock(_ldap_response(0))
    negotiate(sock, "ldap", "h", timeout=5)
    assert sock.sent.startswith(b"\x30") and b"1.3.6.1.4.1.1466.20037" in sock.sent


def test_ldap_failure_raises():
    with pytest.raises(StartTLSError, match="resultCode"):
        negotiate(FakeSock(_ldap_response(1)), "ldap", "h", timeout=5)


def test_mysql_sends_ssl_request():
    payload = b"\x0a" + b"5.7.40\x00" + b"x" * 12          # protocol 10 greeting (not ERR)
    greeting = len(payload).to_bytes(3, "little") + b"\x00" + payload
    sock = FakeSock(greeting)
    negotiate(sock, "mysql", "h", timeout=5)
    # SSL request: 4-byte header (len 32, seq 1) + 32-byte payload
    assert len(sock.sent) == 36
    assert sock.sent[3] == 1                                # sequence id = server_seq + 1
    caps = int.from_bytes(sock.sent[4:8], "little")
    assert caps & starttls._MYSQL_CLIENT_SSL


def test_mysql_err_greeting_raises():
    payload = b"\xff" + b"\x15\x04bad host"
    greeting = len(payload).to_bytes(3, "little") + b"\x00" + payload
    with pytest.raises(StartTLSError):
        negotiate(FakeSock(greeting), "mysql", "h", timeout=5)


def test_closed_connection_raises():
    with pytest.raises(StartTLSError):
        negotiate(FakeSock(b""), "smtp", "h", timeout=5)


# --------------------------------------------------------------------------- #
# Review-fix regressions
# --------------------------------------------------------------------------- #

def test_smtp_hostname_containing_starttls_is_not_a_false_positive():
    # the greeting/EHLO hostname contains "starttls" but the extension is absent
    script = (b"220 starttls.example.com ESMTP\r\n"
              b"250-starttls.example.com Hello\r\n250-PIPELINING\r\n250 8BITMIME\r\n")
    with pytest.raises(StartTLSError, match="advertise STARTTLS"):
        negotiate(FakeSock(script), "smtp", "example.com", timeout=5)


def _mysql_greeting(cap_lower: int) -> bytes:
    payload = (b"\x0a" + b"5.7.40\x00" + b"\x01\x00\x00\x00"      # proto + version + thread id
               + b"A" * 8 + b"\x00"                              # auth-plugin-data-1 + filler
               + cap_lower.to_bytes(2, "little") + b"\x21\x02\x00")  # cap_lower + charset + status
    return len(payload).to_bytes(3, "little") + b"\x00" + payload


def test_mysql_ssl_disabled_raises():
    # capability flags WITHOUT CLIENT_SSL (0x0800) -> clean StartTLSError, like postgres 'N'
    with pytest.raises(StartTLSError, match="SSL disabled"):
        negotiate(FakeSock(_mysql_greeting(0x0001)), "mysql", "h", timeout=5)


def test_mysql_ssl_enabled_proceeds():
    sock = FakeSock(_mysql_greeting(0x0001 | starttls._MYSQL_CLIENT_SSL))
    negotiate(sock, "mysql", "h", timeout=5)
    assert len(sock.sent) == 36                                   # SSLRequest sent
