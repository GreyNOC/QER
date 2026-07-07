import struct

from qer.cert_chain import (_parse_certificate_message, _try_extract_certificate,
                           build_tls12_client_hello)


def _u24(n):
    return struct.pack("!I", n)[1:]


def _cert_msg_body(ders):
    inner = b"".join(_u24(len(d)) + d for d in ders)
    return _u24(len(inner)) + inner


def test_parse_certificate_message_multiple():
    ders = [b"AAAA", b"BBBBBB", b"C"]
    assert _parse_certificate_message(_cert_msg_body(ders)) == ders


def test_parse_certificate_message_empty():
    assert _parse_certificate_message(b"\x00\x00\x00") == []


def test_try_extract_needs_more_then_completes():
    sh = b"\x02" + _u24(4) + b"\x00\x00\x00\x00"          # ServerHello
    body = _cert_msg_body([b"XY", b"Z"])
    cert_msg = b"\x0b" + _u24(len(body)) + body           # Certificate
    full = sh + cert_msg
    assert _try_extract_certificate(full[:-1]) is None     # incomplete -> need more
    assert _try_extract_certificate(full) == [b"XY", b"Z"]  # complete


def test_try_extract_server_hello_done_without_cert():
    shd = b"\x0e" + _u24(0)                                 # ServerHelloDone, no Certificate
    assert _try_extract_certificate(shd) == []


def test_parse_chain_position_by_original_index(monkeypatch):
    from qer import scanner
    from qer.models import CertInfo, QuantumRisk

    def fake_parse(der):
        if der == b"bad":
            raise ValueError("unparseable leaf")
        return CertInfo(subject="s", issuer="i", serial="1",
                        public_key_algorithm="ECDSA", signature_algorithm="ecdsa-with-SHA256",
                        is_self_signed=(der == b"root"), quantum_risk=QuantumRisk.QUANTUM_VULNERABLE)

    monkeypatch.setattr(scanner, "_parse_certificate", fake_parse)
    # The chain is leaf-first. When the leaf (index 0) fails to parse, a surviving
    # CA must NOT be promoted to "leaf" — positions follow the original index.
    chain = scanner._parse_chain([b"bad", b"inter", b"inter2", b"root"])
    assert [c.position for c in chain] == ["intermediate", "intermediate", "root"]
    # When the leaf parses cleanly it is labelled "leaf".
    chain2 = scanner._parse_chain([b"leaf", b"inter", b"root"])
    assert [c.position for c in chain2] == ["leaf", "intermediate", "root"]


def test_recv_exact_respects_deadline():
    import time

    from qer.pqprobe import _recv_exact

    class _NeverRead:                       # proves we don't read past the deadline
        def recv(self, n):
            raise AssertionError("recv called past deadline")

        def settimeout(self, t):
            raise AssertionError("settimeout called past deadline")

    past = time.monotonic() - 1.0           # deadline already elapsed
    assert _recv_exact(_NeverRead(), 4, deadline=past) is None


def test_client_hello_is_tls12_with_sni_and_no_supported_versions():
    rec = build_tls12_client_hello("example.com")
    assert rec[:3] == b"\x16\x03\x01"          # TLS handshake record
    assert rec[5] == 0x01                       # ClientHello
    assert b"\xc0\x2f" in rec                   # offers a TLS 1.2 cipher (ECDHE-RSA-AES128-GCM)
    assert b"example.com" in rec                # SNI present
    # No supported_versions extension -> a 1.2/1.3 server negotiates 1.2.
    # Parse the extension block to assert 0x002b is genuinely absent.
    body = rec[9:]                              # skip record(5) + handshake header(4)
    pos = 2 + 32                                # legacy_version + random
    pos += 1 + body[pos]                        # session_id
    pos += 2 + struct.unpack("!H", body[pos:pos + 2])[0]   # cipher_suites
    pos += 1 + body[pos]                        # compression_methods
    ext_len = struct.unpack("!H", body[pos:pos + 2])[0]; pos += 2
    seen = []
    end = pos + ext_len
    while pos + 4 <= end:
        etype = struct.unpack("!H", body[pos:pos + 2])[0]
        elen = struct.unpack("!H", body[pos + 2:pos + 4])[0]
        seen.append(etype)
        pos += 4 + elen
    assert 0x002B not in seen                    # supported_versions absent
    assert 0x0000 in seen                        # server_name present
