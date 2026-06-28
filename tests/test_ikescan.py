import struct

from qer.ikescan import (_PL_KE, _PL_NONCE, _PL_NOTIFY, _PL_SA, _T_DH, _T_ENCR,
                        _T_INTEG, _T_PRF, _payload, _proposal, _transform,
                        build_sa_init, classify, generate_ike_findings,
                        parse_response)


def _keylen(bits):
    return struct.pack("!HH", 0x800E, bits)


def _response(transforms, resp_spi=b"RESPSPI!", init_spi=b"INITSPI!"):
    """Build a synthetic IKE_SA_INIT *response* carrying one chosen proposal."""
    sa = _payload(_PL_KE, _proposal(1, transforms))
    ke = _payload(_PL_NONCE, struct.pack("!HH", 14, 0) + b"\x00" * 256)
    nonce = _payload(0, b"\x00" * 32)
    payloads = sa + ke + nonce
    header = (init_spi + resp_spi + bytes([_PL_SA, 0x20, 34, 0x20])   # responder flag
              + struct.pack("!II", 0, 28 + len(payloads)))
    return header + payloads


def test_build_sa_init_structure():
    pkt = build_sa_init(initiator_spi=b"ABCDEFGH")
    assert pkt[0:8] == b"ABCDEFGH"
    assert pkt[8:16] == b"\x00" * 8          # responder SPI is zero in the request
    assert pkt[16] == _PL_SA                  # first payload = SA
    assert pkt[17] == 0x20                    # IKEv2
    assert pkt[18] == 34                      # IKE_SA_INIT
    assert pkt[19] == 0x08                    # initiator flag
    assert struct.unpack("!I", pkt[24:28])[0] == len(pkt)   # declared length == actual


def test_parse_response_extracts_chosen_transforms():
    transforms = [
        _transform(False, _T_ENCR, 20, _keylen(256)),   # AES-GCM-16 256
        _transform(False, _T_PRF, 5),                    # HMAC-SHA2-256
        _transform(False, _T_INTEG, 12),                 # HMAC-SHA2-256-128
        _transform(True, _T_DH, 14),                     # MODP-2048
    ]
    r = parse_response(_response(transforms), "vpn.example.com", 500)
    assert r.reachable and r.responder and r.ike_version == "2.0"
    assert r.chosen["encryption"]["name"] == "AES-GCM-16" and r.chosen["encryption"]["keylen"] == 256
    assert r.chosen["dh-group"]["name"] == "MODP-2048"
    assert r.chosen["prf"]["name"] == "HMAC-SHA2-256"
    assert r.chosen["integrity"]["name"] == "HMAC-SHA2-256-128"


def test_encr_keylen_drives_symmetric_risk():
    for keylen, expect in [(256, "pq-safe"), (128, "quantum-weakened")]:
        r = parse_response(_response([_transform(True, _T_ENCR, 20, _keylen(keylen))]))
        classify(r)
        assert r.chosen["encryption"]["quantum_risk"] == expect


def test_legacy_transforms_classified_and_flagged():
    transforms = [
        _transform(False, _T_ENCR, 3),       # 3DES (broken)
        _transform(False, _T_PRF, 2),        # HMAC-SHA1
        _transform(False, _T_INTEG, 2),      # HMAC-SHA1-96 (broken)
        _transform(True, _T_DH, 2),          # MODP-1024 (broken)
    ]
    r = parse_response(_response(transforms))
    classify(r)
    assert r.chosen["dh-group"]["quantum_risk"] == "broken-now"
    ids = {f.id for f in generate_ike_findings(r)}
    assert "QER-IKE-DH" in ids and "QER-IKE-WEAK" in ids


def test_modern_dh_is_quantum_vulnerable():
    r = parse_response(_response([_transform(True, _T_DH, 19)]))   # ECP-256
    classify(r)
    assert r.chosen["dh-group"]["quantum_risk"] == "quantum-vulnerable"
    f = [x for x in generate_ike_findings(r) if x.id == "QER-IKE-DH"]
    assert f and "ECP-256" in f[0].title


def test_invalid_ke_payload_notify():
    notify_body = struct.pack("!BBH", 1, 0, 17) + struct.pack("!H", 19)   # INVALID_KE -> group 19
    pl = _payload(0, notify_body)
    header = (b"INITSPI!" + b"RESPSPI!" + bytes([_PL_NOTIFY, 0x20, 34, 0x20])
              + struct.pack("!II", 0, 28 + len(pl)))
    r = parse_response(header + pl)
    assert r.invalid_ke_group == 19
    assert any(f.id == "QER-IKE-DH" for f in generate_ike_findings(r))


def test_short_or_garbage_response_handled():
    r = parse_response(b"\x00" * 10)
    assert not r.reachable and r.error
    assert generate_ike_findings(r)[0].id == "QER-IKE-UNREACHABLE"


def test_scan_ike_end_to_end_over_loopback_socket():
    # Exercises the real UDP send/recv path of scan_ike() against a local
    # responder (the unit tests above only feed parse_response bytes directly).
    import socket
    import threading

    from qer.ikescan import scan_ike

    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(5)
    port = srv.getsockname()[1]
    response = _response([
        _transform(False, _T_ENCR, 20, _keylen(256)),
        _transform(False, _T_PRF, 5),
        _transform(False, _T_INTEG, 12),
        _transform(True, _T_DH, 19),                    # ECP-256
    ])

    def _responder():
        try:
            _data, addr = srv.recvfrom(4096)
            srv.sendto(response, addr)
        except OSError:
            pass

    t = threading.Thread(target=_responder, daemon=True)
    t.start()
    try:
        r = scan_ike("127.0.0.1", port=port, timeout=3)
    finally:
        srv.close()

    assert r.reachable and r.raw_response_hex
    assert r.chosen["dh-group"]["name"] == "ECP-256"
    assert any(f.id == "QER-IKE-DH" for f in r.findings)
