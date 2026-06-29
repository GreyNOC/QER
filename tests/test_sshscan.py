"""Tests for the SSH transport scanner (qer.sshscan)."""

from __future__ import annotations

import struct

import pytest

from qer.classify import is_pq_algorithm
from qer.models import QuantumRisk, Severity
from qer import sshscan
from qer.sshscan import (SshResult, classify, classify_cipher, classify_hostkey,
                         classify_kex, classify_mac, generate_ssh_findings,
                         parse_kexinit, scan_ssh, _Reader, _read_kexinit_payload)


# --------------------------------------------------------------------------- #
# Wire-format builders (mirror RFC 4253 framing) used to drive the parser.
# --------------------------------------------------------------------------- #

def _namelist(names) -> bytes:
    raw = ",".join(names).encode("ascii")
    return struct.pack("!I", len(raw)) + raw


def build_kexinit_payload(kex, hostkey, enc, mac, comp=("none",)) -> bytes:
    p = bytes([sshscan._MSG_KEXINIT]) + b"\x00" * 16
    p += _namelist(kex) + _namelist(hostkey)
    p += _namelist(enc) + _namelist(enc)          # c2s, s2c
    p += _namelist(mac) + _namelist(mac)
    p += _namelist(comp) + _namelist(comp)
    p += _namelist([]) + _namelist([])            # languages
    p += b"\x00" + struct.pack("!I", 0)           # first_kex_follows + reserved
    return p


def frame_packet(payload: bytes) -> bytes:
    pad = 4
    while (4 + 1 + len(payload) + pad) % 8 != 0:
        pad += 1
    packet_length = 1 + len(payload) + pad
    return struct.pack("!I", packet_length) + bytes([pad]) + payload + b"\x00" * pad


class FakeSock:
    """A socket whose recv() yields a fixed stream in configurable chunk sizes."""

    def __init__(self, data: bytes, chunk: int | None = None):
        self.data, self.pos, self.chunk = data, 0, chunk
        self.sent = bytearray()

    def settimeout(self, _t):
        pass

    def recv(self, n):
        if self.pos >= len(self.data):
            return b""                            # peer closed
        take = min(n, self.chunk) if self.chunk else n
        out = self.data[self.pos:self.pos + take]
        self.pos += len(out)
        return out

    def sendall(self, b):
        self.sent += b

    def close(self):
        pass


_MODERN = dict(
    kex=["sntrup761x25519-sha512@openssh.com", "curve25519-sha256", "ecdh-sha2-nistp256",
         "kex-strict-s-v00@openssh.com"],
    hostkey=["ssh-ed25519", "rsa-sha2-512", "ssh-rsa"],
    enc=["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr"],
    mac=["hmac-sha2-256-etm@openssh.com", "hmac-sha1"],
)


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #

def test_is_pq_recognises_sntrup_and_mlkem():
    assert is_pq_algorithm("sntrup761x25519-sha512@openssh.com")
    assert is_pq_algorithm("mlkem768x25519-sha256")
    assert not is_pq_algorithm("curve25519-sha256")


def test_classify_kex_buckets():
    assert classify_kex("sntrup761x25519-sha512@openssh.com")[0] == QuantumRisk.PQ_SAFE
    assert classify_kex("curve25519-sha256")[0] == QuantumRisk.QUANTUM_VULNERABLE
    assert classify_kex("ecdh-sha2-nistp384")[0] == QuantumRisk.QUANTUM_VULNERABLE
    assert classify_kex("diffie-hellman-group14-sha1")[0] == QuantumRisk.BROKEN_NOW
    assert classify_kex("diffie-hellman-group1-sha1")[0] == QuantumRisk.BROKEN_NOW


def test_classify_kex_gss_modern_group_not_broken():
    # regression: "group1" substring must not flag group14/16/18 as broken
    assert classify_kex("gss-group14-sha256-toWM5Slw5Ew8Mqkay+al2g==")[0] == QuantumRisk.QUANTUM_VULNERABLE
    assert classify_kex("gss-group16-sha512-toWM5Slw5Ew8Mqkay+al2g==")[0] == QuantumRisk.QUANTUM_VULNERABLE
    assert classify_kex("gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==")[0] == QuantumRisk.BROKEN_NOW
    assert classify_kex("diffie-hellman-group14-sha256")[0] == QuantumRisk.QUANTUM_VULNERABLE
    assert classify_kex("diffie-hellman-group18-sha512")[0] == QuantumRisk.QUANTUM_VULNERABLE


def test_classify_hostkey_buckets():
    assert classify_hostkey("ssh-ed25519")[0] == QuantumRisk.QUANTUM_VULNERABLE
    assert classify_hostkey("rsa-sha2-512")[0] == QuantumRisk.QUANTUM_VULNERABLE
    assert classify_hostkey("ssh-rsa")[0] == QuantumRisk.BROKEN_NOW       # SHA-1 signature
    assert classify_hostkey("ssh-dss")[0] == QuantumRisk.BROKEN_NOW


def test_classify_cipher_and_mac_buckets():
    assert classify_cipher("chacha20-poly1305@openssh.com")[0] == QuantumRisk.PQ_SAFE
    assert classify_cipher("aes256-gcm@openssh.com")[0] == QuantumRisk.PQ_SAFE
    assert classify_cipher("aes128-ctr")[0] == QuantumRisk.QUANTUM_WEAKENED
    assert classify_cipher("3des-cbc")[0] == QuantumRisk.BROKEN_NOW
    assert classify_mac("hmac-sha2-256")[0] == QuantumRisk.PQ_SAFE
    assert classify_mac("hmac-sha1")[0] == QuantumRisk.BROKEN_NOW
    assert classify_mac("hmac-md5")[0] == QuantumRisk.BROKEN_NOW


# --------------------------------------------------------------------------- #
# KEXINIT parsing + PQ verdict
# --------------------------------------------------------------------------- #

def test_parse_kexinit_roundtrip():
    payload = build_kexinit_payload(_MODERN["kex"], _MODERN["hostkey"],
                                    _MODERN["enc"], _MODERN["mac"])
    lists = parse_kexinit(payload)
    assert lists["kex"] == _MODERN["kex"]
    assert lists["host_key"] == _MODERN["hostkey"]
    assert lists["enc_s2c"] == _MODERN["enc"]
    assert lists["mac_c2s"] == _MODERN["mac"]


def test_classify_sets_pq_preferred():
    r = SshResult(host="h", port=22, kex_algorithms=_MODERN["kex"],
                  host_key_algorithms=_MODERN["hostkey"], ciphers=_MODERN["enc"],
                  macs=_MODERN["mac"])
    classify(r)
    # signalling token must be skipped when picking the preferred kex
    assert r.preferred_kex == "sntrup761x25519-sha512@openssh.com"
    assert r.pq_kex_offered and r.pq_kex_preferred


def test_classify_pq_offered_not_preferred():
    r = SshResult(host="h", port=22,
                  kex_algorithms=["curve25519-sha256", "sntrup761x25519-sha512@openssh.com"])
    classify(r)
    assert r.pq_kex_offered and not r.pq_kex_preferred


def test_classify_no_pq():
    r = SshResult(host="h", port=22, kex_algorithms=["ecdh-sha2-nistp256", "curve25519-sha256"])
    classify(r)
    assert not r.pq_kex_offered and not r.pq_kex_preferred


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #

def _findings(kex, hostkey=("ssh-ed25519",), enc=("aes256-gcm@openssh.com",),
              mac=("hmac-sha2-256",)):
    r = SshResult(host="h", port=22, reachable=True, kex_algorithms=list(kex),
                  host_key_algorithms=list(hostkey), ciphers=list(enc), macs=list(mac))
    classify(r)
    return {f.id: f for f in generate_ssh_findings(r)}


def test_findings_pq_preferred_is_clean():
    ids = _findings(["sntrup761x25519-sha512@openssh.com", "curve25519-sha256"])
    assert "QER-SSH-PQ-OK" in ids
    assert "QER-SSH-KEX-HNDL" not in ids


def test_findings_classical_only_flags_hndl():
    ids = _findings(["curve25519-sha256", "ecdh-sha2-nistp256"])
    assert "QER-SSH-KEX-HNDL" in ids
    assert ids["QER-SSH-KEX-HNDL"].category == "hndl"


def test_findings_partial_pq():
    ids = _findings(["curve25519-sha256", "sntrup761x25519-sha512@openssh.com"])
    assert "QER-SSH-PQ-PARTIAL" in ids


def test_findings_broken_algorithms():
    ids = _findings(["curve25519-sha256"], enc=["3des-cbc", "aes256-ctr"],
                    mac=["hmac-md5", "hmac-sha2-256"])
    assert "QER-SSH-WEAK" in ids
    assert ids["QER-SSH-WEAK"].severity == Severity.HIGH


def test_unreachable_finding():
    out = generate_ssh_findings(SshResult(host="h", port=22, reachable=False, error="boom"))
    assert out[0].id == "QER-SSH-UNREACHABLE"


# --------------------------------------------------------------------------- #
# Buffered reader: regression for ident + KEXINIT in one TCP segment
# --------------------------------------------------------------------------- #

def test_reader_handles_ident_and_packet_in_one_recv():
    payload = build_kexinit_payload(_MODERN["kex"], _MODERN["hostkey"],
                                    _MODERN["enc"], _MODERN["mac"])
    stream = b"SSH-2.0-OpenSSH_9.6p1\r\n" + frame_packet(payload)
    reader = _Reader(FakeSock(stream, chunk=None), deadline=1e18)
    assert reader.read_ident_line() == "SSH-2.0-OpenSSH_9.6p1"
    got = _read_kexinit_payload(reader)
    assert parse_kexinit(got)["kex"] == _MODERN["kex"]


def test_reader_skips_preamble_lines():
    payload = build_kexinit_payload(_MODERN["kex"], _MODERN["hostkey"],
                                    _MODERN["enc"], _MODERN["mac"])
    stream = (b"Authorized access only\r\n"
              b"SSH-2.0-OpenSSH_9.6\r\n" + frame_packet(payload))
    reader = _Reader(FakeSock(stream, chunk=7), deadline=1e18)   # tiny chunks
    assert reader.read_ident_line() == "SSH-2.0-OpenSSH_9.6"
    assert parse_kexinit(_read_kexinit_payload(reader))["kex"] == _MODERN["kex"]


def test_scan_ssh_end_to_end(monkeypatch):
    payload = build_kexinit_payload(_MODERN["kex"], _MODERN["hostkey"],
                                    _MODERN["enc"], _MODERN["mac"])
    stream = b"SSH-2.0-OpenSSH_9.6\r\n" + frame_packet(payload)
    monkeypatch.setattr(sshscan.socket, "create_connection",
                        lambda *a, **k: FakeSock(stream))
    r = scan_ssh("example.test", port=22, timeout=5)
    assert r.reachable and r.software == "OpenSSH_9.6"
    assert r.pq_kex_preferred
    assert any(f.id == "QER-SSH-PQ-OK" for f in r.findings)


def test_scan_ssh_implausible_length_is_handled(monkeypatch):
    # ident then a packet claiming a gigantic length -> must not allocate / hang
    stream = b"SSH-2.0-OpenSSH_9.6\r\n" + struct.pack("!I", 0xFFFFFFFF) + b"\x00" * 8
    monkeypatch.setattr(sshscan.socket, "create_connection",
                        lambda *a, **k: FakeSock(stream))
    r = scan_ssh("example.test", port=22, timeout=5)
    assert r.reachable and "implausible" in (r.error or "")
