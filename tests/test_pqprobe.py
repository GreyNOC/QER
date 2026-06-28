import struct

from qer.pqprobe import (PQ_GROUPS, X25519_GROUP, _HRR_RANDOM,
                        _interpret_preference, _is_hello_retry,
                        _selected_group_from_server_hello, _x25519_key_share,
                        build_client_hello)


def make_server_hello(group, hrr=True):
    """Synthesize a ServerHello / HelloRetryRequest handshake message body."""
    ext = b""
    ks = struct.pack("!H", group)                       # key_share selected_group
    ext += struct.pack("!HH", 0x0033, len(ks)) + ks
    sv = struct.pack("!H", 0x0304)
    ext += struct.pack("!HH", 0x002B, len(sv)) + sv     # supported_versions: TLS 1.3
    random = _HRR_RANDOM if hrr else b"\x00" * 32
    body = (b"\x03\x03" + random + b"\x00" + b"\x13\x01" + b"\x00"
            + struct.pack("!H", len(ext)) + ext)
    return b"\x02" + struct.pack("!I", len(body))[1:] + body


def test_client_hello_is_well_formed_and_offers_group():
    rec = build_client_hello("example.com", [PQ_GROUPS["X25519MLKEM768"]])
    assert rec[:3] == b"\x16\x03\x01"        # TLS handshake record
    assert rec[5] == 0x01                    # ClientHello
    assert b"\x11\xec" in rec                # X25519MLKEM768 codepoint advertised


def test_hrr_random_is_the_rfc8446_value():
    # Regression for the corrupted magic constant that silently broke PQ-enforce
    # detection (probe_preference always returned "tolerate").
    from qer.pqprobe import _HRR_RANDOM
    assert len(_HRR_RANDOM) == 32
    assert _HRR_RANDOM == bytes.fromhex(
        "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


def test_detects_hello_retry_request():
    msg = make_server_hello(PQ_GROUPS["X25519MLKEM768"], hrr=True)
    assert _is_hello_retry(msg) is True
    assert _selected_group_from_server_hello(msg) == PQ_GROUPS["X25519MLKEM768"]


def test_non_hrr_server_hello_not_flagged_as_retry():
    msg = make_server_hello(PQ_GROUPS["X25519MLKEM768"], hrr=False)
    assert _is_hello_retry(msg) is False


def test_selected_group_roundtrip_for_each_group():
    for name, code in PQ_GROUPS.items():
        msg = make_server_hello(code, hrr=True)
        assert _selected_group_from_server_hello(msg) == code, name


def test_x25519_key_share_is_32_bytes():
    share = _x25519_key_share()
    assert share is not None and len(share) == 32


def test_client_hello_with_key_share_offers_x25519_share():
    share = _x25519_key_share()
    pq = PQ_GROUPS["X25519MLKEM768"]
    rec = build_client_hello("example.com", [pq, X25519_GROUP], {X25519_GROUP: share})
    # x25519 group code 0x001D followed by a 0x0020 (32-byte) key_exchange length
    assert struct.pack("!HH", X25519_GROUP, 32) in rec
    assert share in rec


def test_preference_rule_enforce_vs_tolerate():
    pq = PQ_GROUPS["X25519MLKEM768"]
    # HRR demanding the PQ group despite our x25519 share => enforce
    assert _interpret_preference(True, pq, pq) == "enforce"
    # HRR for x25519, or a completed ServerHello => tolerate
    assert _interpret_preference(True, X25519_GROUP, pq) == "tolerate"
    assert _interpret_preference(False, None, pq) == "tolerate"


class _FakeSock:
    def __init__(self, data):
        self._data = data

    def recv(self, n):
        if not self._data:
            return b""
        chunk, self._data = self._data[:n], self._data[n:]
        return chunk


def test_recv_exact_is_all_or_nothing():
    from qer.pqprobe import _recv_exact
    assert _recv_exact(_FakeSock(b"abcd"), 4) == b"abcd"
    # truncated stream must yield None, never a partial buffer
    assert _recv_exact(_FakeSock(b"ab"), 4) is None


def test_read_record_rejects_truncated_payload():
    from qer.pqprobe import _read_record
    # header declares a 10-byte payload but only 3 bytes follow
    data = b"\x16\x03\x03" + struct.pack("!H", 10) + b"\x02\x00\x00"
    assert _read_record(_FakeSock(data)) is None


def test_alert_classification():
    from qer.pqprobe import _alert_means_unsupported
    assert _alert_means_unsupported(b"\x02\x28") is False   # fatal handshake_failure(40)
    assert _alert_means_unsupported(b"\x02\x47") is False    # insufficient_security(71)
    assert _alert_means_unsupported(b"\x02\x50") is None     # internal_error(80) -> inconclusive
    assert _alert_means_unsupported(b"\x01\x46") is None     # protocol_version(70) -> inconclusive
    assert _alert_means_unsupported(b"") is None             # empty payload, no crash


def test_extension_walk_survives_lying_length():
    # An extension whose declared length overflows the block must not crash or
    # misparse; _selected_group_from_server_hello returns None gracefully.
    body = (b"\x02" + struct.pack("!I", 41)[1:]            # handshake header
            + b"\x03\x03" + _HRR_RANDOM + b"\x00" + b"\x13\x01" + b"\x00"
            + struct.pack("!H", 6)                          # extensions length = 6
            + struct.pack("!HH", 0x0033, 0xFFFF))           # key_share, elen lies (65535)
    assert _selected_group_from_server_hello(body) is None
