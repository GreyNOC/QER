"""Regression tests for the v0.2.1 whole-project audit.

Each test pins a bug that a multi-agent review found and adversarial verification
confirmed, so the fix can't silently regress. Grouped by module; the finding id
(e.g. B6, A2C2) is noted so the audit trail stays traceable.
"""

import dataclasses

import pytest

from qer.classify import classify_signature, is_pq_algorithm, parse_cipher
from qer.models import (QuantumRisk, ScanResult, Severity,
                        scan_result_from_dict, to_serializable)


# --------------------------------------------------------------------------- #
# classify.py
# --------------------------------------------------------------------------- #

def test_anon_suites_are_forward_secret():        # B5
    """ADH-/AECDH- suites are ephemeral: forward-secret, not static RSA."""
    adh = parse_cipher("ADH-AES256-GCM-SHA384")
    assert adh.key_exchange == "DHE"
    assert adh.forward_secret is True
    assert adh.authentication == "anon"

    aecdh = parse_cipher("AECDH-AES128-SHA")
    assert aecdh.key_exchange == "ECDHE"
    assert aecdh.forward_secret is True


@pytest.mark.parametrize("name", [
    "ecdsa-with-SHAKE256", "id-ecdsa-with-shake256", "RSASSA-PSS-SHAKE128",
])
def test_shake_signatures_not_flagged_sha1(name):     # B6
    risk, sev, hash_name, _ = classify_signature(name)
    assert hash_name != "sha1"
    assert risk != QuantumRisk.BROKEN_NOW or "shake" in (hash_name or "")


@pytest.mark.parametrize("name", ["md2WithRSAEncryption", "md4WithRSAEncryption"])
def test_md2_md4_are_broken_now(name):                # B6
    risk, sev, hash_name, _ = classify_signature(name)
    assert risk == QuantumRisk.BROKEN_NOW
    assert sev == Severity.CRITICAL


@pytest.mark.parametrize("name", ["xmss", "XMSS-SHA2_10_256", "hss-lms", "LMS"])
def test_stateful_hash_sigs_are_pq(name):             # classify improvement #7
    assert is_pq_algorithm(name) is True


# --------------------------------------------------------------------------- #
# models.py
# --------------------------------------------------------------------------- #

def test_unknown_risk_label_fails_to_vulnerable():    # B13
    assert QuantumRisk.from_label("some-future-risk") == QuantumRisk.QUANTUM_VULNERABLE
    assert QuantumRisk.from_label(None) == QuantumRisk.QUANTUM_VULNERABLE
    # Known labels still round-trip.
    assert QuantumRisk.from_label("pq-safe") == QuantumRisk.PQ_SAFE


def test_legacy_only_round_trips():                   # A1 support
    sr = ScanResult(host="h", port=443, reachable=True, legacy_only=True)
    back = scan_result_from_dict(to_serializable(sr))
    assert back.legacy_only is True


# --------------------------------------------------------------------------- #
# pqprobe.py
# --------------------------------------------------------------------------- #

def test_probe_pq_all_errored_is_untestable(monkeypatch):   # A2C2
    from qer import pqprobe
    monkeypatch.setattr(pqprobe, "probe_group", lambda *a, **k: None)
    res = pqprobe.probe_pq("192.0.2.1", 443, groups=["X25519MLKEM768"])
    assert res["testable"] is False
    assert res["pq_supported"] is None                # not a confident False


def test_probe_pq_partial_evidence_is_testable(monkeypatch):  # A2C2
    from qer import pqprobe
    seen = {"n": 0}

    def fake(host, port, name, *a, **k):
        seen["n"] += 1
        return name == "X25519MLKEM768"               # one supported, one rejected
    monkeypatch.setattr(pqprobe, "probe_group", fake)
    monkeypatch.setattr(pqprobe, "probe_preference", lambda *a, **k: "tolerate")
    res = pqprobe.probe_pq("192.0.2.1", 443,
                           groups=["X25519MLKEM768", "SecP256r1MLKEM768"],
                           check_preference=False)
    assert res["testable"] is True
    assert res["pq_supported"] is True


def test_default_probe_groups_include_p256_hybrid():  # A7
    from qer.pqprobe import DEFAULT_PROBE_GROUPS, PQ_GROUPS
    assert "SecP256r1MLKEM768" in DEFAULT_PROBE_GROUPS
    assert all(g in PQ_GROUPS for g in DEFAULT_PROBE_GROUPS)


# --------------------------------------------------------------------------- #
# rules.py
# --------------------------------------------------------------------------- #

def _facts(**scan):
    base = {"primitives": [], "certificates": []}
    base.update(scan)
    return base


def test_rule_multi_key_is_implicit_and():            # B3
    from qer.rules import match
    facts = _facts(negotiated_version="TLSv1.2",
                   certificates=[{"public_key_algorithm": "RSA"}])
    cond = {"scan": {"negotiated_version": "TLSv1.3"},      # false
            "certificate": {"public_key_algorithm": "RSA"}}  # true
    assert match(cond, facts) is False                # both legs must hold
    cond2 = {"scan": {"negotiated_version": "TLSv1.2"},
             "certificate": {"public_key_algorithm": "RSA"}}
    assert match(cond2, facts) is True


def test_rule_empty_condition_never_fires():          # B3
    from qer.rules import match
    assert match({}, _facts()) is False


# --------------------------------------------------------------------------- #
# passive.py
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("curve,kind", [
    ("unknown-4588", "pq"),          # X25519MLKEM768
    ("unknown-25497", "pq"),         # X25519Kyber768Draft00
    ("unknown-4587", "pq"),          # SecP256r1MLKEM768
    ("x25519", "classical"),
    ("unknown-99999", "classical"),  # a genuinely unknown codepoint stays classical
    ("unknown-abc", "classical"),    # QAQC C9: non-numeric suffix -> ValueError fallback
    ("unknown-", "classical"),       # QAQC C9: empty suffix
    ("", "none"),
])
def test_zeek_unknown_codepoints_classified(curve, kind):   # B14 + C9
    from qer.passive import classify_curve
    assert classify_curve(curve) == kind


# --------------------------------------------------------------------------- #
# ikescan.py
# --------------------------------------------------------------------------- #

def test_ike_encr_codepoints_match_iana():            # A3
    from qer.ikescan import _ENCR
    assert _ENCR[16][0] == "AES-CCM-16"
    assert _ENCR[23][0] == "Camellia-CBC"


def test_ike_mlkem_groups_are_pq():                   # A9 (grounded improvement)
    from qer.ikescan import _DH
    assert _DH[36][1] == QuantumRisk.PQ_SAFE          # ML-KEM-768
    assert _DH[35][1] == QuantumRisk.PQ_SAFE
    assert _DH[37][1] == QuantumRisk.PQ_SAFE
    assert _DH[19][1] == QuantumRisk.QUANTUM_VULNERABLE   # ECP-256 still classical


# --------------------------------------------------------------------------- #
# downgrade.py
# --------------------------------------------------------------------------- #

def test_proto_downgrade_risk_from_landed_version():  # B12
    from qer.downgrade import compare
    scan = ScanResult(host="h", port=443, reachable=True, negotiated_version="TLSv1.2")
    prev = {"negotiated_version": "TLSv1.3"}
    dg = [f for f in compare(scan, prev) if f.id == "QER-DG-PROTO"]
    assert dg and dg[0].quantum_risk == QuantumRisk.QUANTUM_VULNERABLE  # not broken-now

    scan2 = ScanResult(host="h", port=443, reachable=True, negotiated_version="TLSv1")
    dg2 = [f for f in compare(scan2, {"negotiated_version": "TLSv1.2"}) if f.id == "QER-DG-PROTO"]
    assert dg2 and dg2[0].quantum_risk == QuantumRisk.BROKEN_NOW


# --------------------------------------------------------------------------- #
# codescan.py
# --------------------------------------------------------------------------- #

def _scan(text):
    from qer.codescan import _scan_source
    return {f.id for f in _scan_source("x", text)}


def test_des_prose_not_flagged():                     # B15
    assert "QER-CODE-WEAKCIPHER" not in _scan("la sauvegarde des fichiers importants")
    assert "QER-CODE-WEAKCIPHER" in _scan("crypto.createCipheriv('des-ede3-cbc', k, iv)")
    assert "QER-CODE-WEAKCIPHER" in _scan('Cipher.getInstance("DES")')


def test_x448_hex_literal_not_flagged():              # B15
    assert "QER-CODE-EDDSA" not in _scan("const mask = 0x448;")
    assert "QER-CODE-EDDSA" not in _scan("addr = 0x25519;")
    assert "QER-CODE-EDDSA" in _scan("kex = 'X25519MLKEM768'")


def test_x25519_camelcase_still_flagged():            # QAQC C1 (regression of B15 fix)
    assert "QER-CODE-EDDSA" in _scan("const clientX25519Key = generateX25519();")
    assert "QER-CODE-EDDSA" in _scan("priv := newX448()")


def test_falcon_framework_not_flagged():              # B15
    assert "QER-CODE-PQ" not in _scan("import falcon\napp = falcon.App()")
    assert "QER-CODE-PQ" in _scan("sig = falcon_512.sign(msg)")


def test_sha1_jca_transform_flagged():                # B17
    assert "QER-CODE-SHA1" in _scan('Signature.getInstance("SHA1withRSA")')
    assert "QER-CODE-SHA1" in _scan("mac = Mac.getInstance('HmacSHA1')")


def test_alg_none_single_quoted_flagged():            # B17
    assert "QER-CODE-JWT-NONE" in _scan("{ 'alg': 'none' }")
    assert "QER-CODE-JWT-NONE" in _scan("algorithm: 'none'")


def test_python_jose_dependency_flagged():            # B17
    from qer.codescan import _scan_manifest
    ids = {f.id for f in _scan_manifest("requirements.txt", "requirements.txt",
                                        "python-jose==3.3.0\n")}
    assert "QER-CODE-DEP" in ids


# --------------------------------------------------------------------------- #
# siem/zeek.py — emitted detection script
# --------------------------------------------------------------------------- #

def test_zeek_script_tls13_forward_secret():          # C1
    from qer.siem.zeek import to_zeek
    script = to_zeek([])
    # TLS 1.3 suites must be recognised as forward-secret so the emitted script
    # doesn't raise No_Forward_Secrecy on every TLS 1.3 connection.
    assert "TLS_AES_" in script and "TLS_CHACHA20_" in script
    # and the raw-codepoint PQ group spellings older Zeek logs are recognised.
    assert "unknown-4588" in script


# --------------------------------------------------------------------------- #
# scanner.py
# --------------------------------------------------------------------------- #

def test_legacy_only_endpoint_retries_at_seclevel0(monkeypatch):   # A1
    import ssl as _ssl

    from qer import scanner
    from qer.models import AssetProfile

    calls = {"n": 0}

    class _FakeSock:
        def version(self):
            return "TLSv1"

        def cipher(self):
            return ("ECDHE-RSA-AES256-SHA", "TLSv1", 256)

        def getpeercert(self, binary_form=False):
            return None

        def close(self):
            pass

    def fake_connect(host, port, ctx, timeout, starttls=None):
        calls["n"] += 1
        if calls["n"] == 1:                      # the default-seclevel handshake fails
            raise _ssl.SSLError("TLSV1_ALERT_PROTOCOL_VERSION")
        return _FakeSock()                       # the seclevel0 retry succeeds

    monkeypatch.setattr(scanner, "_connect", fake_connect)
    r = scanner.scan_endpoint(AssetProfile(host="127.0.0.1", port=443),
                              enumerate_versions=False, do_pq_probe=False, do_chain=False)
    assert r.reachable is True                   # not reported unreachable
    assert r.legacy_only is True
    assert r.negotiated_version == "TLSv1"
    assert calls["n"] == 2                        # retried exactly once


# --------------------------------------------------------------------------- #
# report.py — SSH console
# --------------------------------------------------------------------------- #

def test_ssh_incomplete_scan_no_confident_verdict():   # C4
    from qer.report import render_ssh_console
    from qer.sshscan import SshResult

    # Banner read, but KEXINIT failed: reachable=True, error set, no algorithms.
    r = SshResult(host="h", port=22, reachable=True,
                  error="timeout reading KEXINIT", banner="SSH-2.0-Foo")
    text = render_ssh_console(r, color=False)
    assert "scan incomplete" in text
    assert "no post-quantum key exchange" not in text   # don't assert off empty data


# --------------------------------------------------------------------------- #
# cli.py
# --------------------------------------------------------------------------- #

def test_cli_rejects_unknown_pq_group():              # A2C2
    from qer.cli import main
    # A typo'd group must error (exit 1) instead of silently scanning as classical.
    assert main(["scan", "example.com", "--pq-groups", "x25519mlkem768_typo",
                 "--no-color", "--quiet"]) == 1


def test_cli_normalizes_pq_group_case(monkeypatch):   # A2C2
    import qer.cli as cli
    captured = {}

    def fake_build_reports(profiles, **kw):
        captured["pq_groups"] = kw.get("pq_groups")
        return [], {"tool_version": "test"}, []

    monkeypatch.setattr(cli, "build_reports", fake_build_reports)
    # lowercase input should be canonicalised to the registry spelling, not rejected
    rc = cli.main(["scan", "example.com", "--pq-groups", "x25519mlkem768",
                   "--no-color", "--quiet"])
    assert captured.get("pq_groups") == ["X25519MLKEM768"]
    assert rc == 0


def test_discover_preserves_target_annotations(monkeypatch, tmp_path):   # C7
    import qer.cli as cli
    tf = tmp_path / "targets.txt"
    tf.write_text("10.0.0.5:443 sensitivity=5 shelf_life=15 expect_pq=true\n")

    monkeypatch.setattr(cli, "discover_services",
                        lambda hosts, ports, **k: [("10.0.0.5", 8443)])
    captured = {}

    def fake_build_reports(profiles, **kw):
        captured["profiles"] = list(profiles)
        return [], {"tool_version": "t"}, []

    monkeypatch.setattr(cli, "build_reports", fake_build_reports)
    rc = cli.main(["scan", "-f", str(tf), "--discover", "--no-color", "--quiet"])
    assert rc == 0
    p = captured["profiles"][0]
    # discovered service inherits the seed host's business context (port swapped)
    assert (p.host, p.port) == ("10.0.0.5", 8443)
    assert p.sensitivity == 5 and p.shelf_life_years == 15 and p.expect_pq is True


# --------------------------------------------------------------------------- #
# scoring.py — PQ-unverified messaging (C3)
# --------------------------------------------------------------------------- #

def test_pq_unverified_distinguishes_disabled_from_errored():   # C3
    from qer.models import AssetProfile, ScanResult
    from qer.scoring import generate_findings, score_endpoint

    prof = AssetProfile(host="h", port=443, expect_pq=True)

    def unverified(pq_probe_ran):
        scan = ScanResult(host="h", port=443, reachable=True, negotiated_version="TLSv1.3",
                          pq_testable=False, pq_probe_ran=pq_probe_ran)
        fs = generate_findings(prof, scan, score_endpoint(prof, scan))
        return next(f for f in fs if f.id == "QER-PQ-UNVERIFIED")

    assert "disabled" in unverified(False).title            # --no-pq
    assert "errored" in unverified(True).title               # probe ran, all groups errored


# --------------------------------------------------------------------------- #
# report.py / scanner.py — legacy_only surfacing + retry failure (C4, C5, C6)
# --------------------------------------------------------------------------- #

def test_legacy_only_shown_in_console():                # C4
    from qer.models import AssetProfile, EndpointReport, ScanResult
    from qer.report import render_console
    from qer.scoring import score_endpoint

    prof = AssetProfile(host="h", port=443)
    scan = ScanResult(host="h", port=443, reachable=True, legacy_only=True,
                      negotiated_version="TLSv1", negotiated_cipher="ECDHE-RSA-AES256-SHA",
                      key_exchange="ECDHE")
    rep = EndpointReport(profile=prof, scan=scan, scores=score_endpoint(prof, scan))
    text = render_console([rep], {"tool_version": "test"}, color=False)
    assert "legacy-only" in text


def test_legacy_retry_failure_is_unreachable(monkeypatch):   # C5
    import ssl as _ssl

    from qer import scanner
    from qer.models import AssetProfile

    calls = {"n": 0}

    def fake_connect(host, port, ctx, timeout, starttls=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise _ssl.SSLError("proto")        # default-seclevel handshake fails
        raise OSError("refused on retry")       # seclevel0 retry also fails

    monkeypatch.setattr(scanner, "_connect", fake_connect)
    r = scanner.scan_endpoint(AssetProfile(host="127.0.0.1", port=443),
                              enumerate_versions=False, do_pq_probe=False, do_chain=False)
    assert r.reachable is False
    assert "OSError" in (r.error or "")
    assert calls["n"] == 2 and r.legacy_only is False


def test_certkey_primitive_when_leaf_unparseable(monkeypatch):   # C6
    from qer import scanner
    from qer.models import AssetProfile, CertInfo, QuantumRisk

    class _FakeSock:
        def version(self):
            return "TLSv1.3"

        def cipher(self):
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        def getpeercert(self, binary_form=False):
            return None                          # no stdlib leaf DER

        def close(self):
            pass

    def fake_parse(der):
        if der == b"bad":
            raise ValueError("unparseable leaf")
        return CertInfo(subject="s", issuer="i", serial="1", public_key_algorithm="RSA",
                        public_key_bits=2048, signature_algorithm="sha256WithRSAEncryption",
                        is_self_signed=(der == b"root"), quantum_risk=QuantumRisk.QUANTUM_VULNERABLE)

    monkeypatch.setattr(scanner, "_connect", lambda *a, **k: _FakeSock())
    monkeypatch.setattr(scanner, "fetch_certificate_chain", lambda *a, **k: [b"bad", b"inter", b"root"])
    monkeypatch.setattr(scanner, "_parse_certificate", fake_parse)

    r = scanner.scan_endpoint(AssetProfile(host="127.0.0.1", port=443),
                              enumerate_versions=False, do_pq_probe=False, do_chain=True)
    # leaf failed to parse: no cert is labelled "leaf", but a certificate-key
    # primitive is still emitted (from the first surviving cert).
    assert r.certificates and all(c.position != "leaf" for c in r.certificates)
    assert any(p.role == "certificate-key" for p in r.primitives)


# --------------------------------------------------------------------------- #
# starttls.py — read caps (C8)
# --------------------------------------------------------------------------- #

def test_starttls_read_caps():                          # C8
    import time

    from qer import starttls
    from qer.starttls import StartTLSError, _Net, _read_multiline_smtp

    net = _Net(sock=None, deadline=time.monotonic() + 5)
    with pytest.raises(StartTLSError, match="too large"):
        net.read_exact(starttls._MAX_READ + 1)          # cap checked before touching the socket

    class _Flood:
        def settimeout(self, t):
            pass

        def recv(self, n):
            return b"250-x\r\n"                          # endless continuation lines

        def sendall(self, d):
            pass

    net2 = _Net(sock=_Flood(), deadline=time.monotonic() + 5)
    with pytest.raises(StartTLSError, match="too many"):
        _read_multiline_smtp(net2)
