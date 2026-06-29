"""Tests for the declarative rule engine (qer.rules)."""

from __future__ import annotations

import json

import pytest

from qer.models import (CertInfo, CryptoPrimitive, Finding, QuantumRisk,
                        ScanResult, Severity)
from qer.rules import (BUILTIN_PACK, RuleError, _apply_op, evaluate_rules,
                       facts_from_scan, load_pack, load_rule_packs, match,
                       match_unknown_keys)


def _scan(version="TLSv1.3", cipher="AES-256", detail="GCM", kex="ECDHE",
          supported=("TLSv1.3", "TLSv1.2"), reachable=True, cert_alg="ECDSA",
          pq=None):
    return ScanResult(
        host="h", port=443, reachable=reachable, negotiated_version=version,
        negotiated_cipher=cipher, key_exchange=kex, forward_secret=True,
        supported_versions=list(supported), pq_kex_negotiated=pq,
        primitives=[
            CryptoPrimitive(role="cipher", algorithm=cipher, detail=detail,
                            quantum_risk=QuantumRisk.PQ_SAFE, bits=256),
            CryptoPrimitive(role="key-exchange", algorithm=kex,
                            quantum_risk=QuantumRisk.QUANTUM_VULNERABLE),
        ],
        certificates=[CertInfo(subject="cn=h", issuer="ca", serial="1",
                               public_key_algorithm=cert_alg, signature_algorithm="ecdsa-with-SHA256",
                               position="leaf", public_key_bits=256, days_to_expiry=40,
                               quantum_risk=QuantumRisk.QUANTUM_VULNERABLE)])


# --------------------------------------------------------------------------- #
# Match DSL
# --------------------------------------------------------------------------- #

def test_scan_field_ops():
    facts = facts_from_scan(_scan())
    assert match({"scan": {"key_exchange": "ecdhe"}}, facts)            # equality, ci
    assert match({"scan": {"negotiated_version_contains": "1.3"}}, facts)
    assert match({"scan": {"supported_versions_has": "TLSv1.2"}}, facts)
    assert not match({"scan": {"supported_versions_has": "TLSv1.0"}}, facts)
    assert match({"scan": {"key_exchange_in": ["ECDHE", "DHE"]}}, facts)
    assert match({"scan": {"forward_secret": True}}, facts)


def test_primitive_and_certificate_match():
    facts = facts_from_scan(_scan(detail="CBC"))
    assert match({"primitive": {"role": "cipher", "detail_contains": "cbc"}}, facts)
    assert not match({"primitive": {"role": "cipher", "detail_contains": "gcm"}}, facts)
    assert match({"certificate": {"position": "leaf", "public_key_algorithm_contains": "ecdsa"}}, facts)
    assert match({"certificate": {"public_key_bits_lt": 384}}, facts)
    assert not match({"certificate": {"public_key_bits_gt": 384}}, facts)


def test_boolean_combinators():
    facts = facts_from_scan(_scan())
    assert match({"all": [{"scan": {"reachable": True}},
                          {"scan": {"forward_secret": True}}]}, facts)
    assert match({"any": [{"scan": {"key_exchange": "RSA"}},
                          {"scan": {"key_exchange": "ECDHE"}}]}, facts)
    assert match({"not": {"scan": {"key_exchange": "RSA"}}}, facts)


def test_nonempty_and_exists():
    facts = facts_from_scan(_scan(supported=("TLSv1.3",)))
    assert match({"scan": {"supported_versions_nonempty": True}}, facts)
    assert match({"scan": {"negotiated_cipher_exists": True}}, facts)
    weak = facts_from_scan(_scan())
    assert not match({"scan": {"weak_versions_nonempty": True}}, weak)


# --------------------------------------------------------------------------- #
# Built-in pack behaviour
# --------------------------------------------------------------------------- #

def test_builtin_cbc_fires():
    packs, errs = load_rule_packs()
    assert not errs
    findings = evaluate_rules(packs, _scan(detail="CBC"))
    ids = {f.id for f in findings}
    assert "QER-RULE-CBC-MODE" in ids
    cbc = next(f for f in findings if f.id == "QER-RULE-CBC-MODE")
    assert cbc.confidence == 0.85 and cbc.rule == "qer-builtin/QER-RULE-CBC-MODE"


def test_builtin_no_tls13_fires_when_absent():
    packs, _ = load_rule_packs()
    fires = evaluate_rules(packs, _scan(version="TLSv1.2", supported=("TLSv1.2", "TLSv1.1")))
    assert "QER-RULE-NO-TLS13" in {f.id for f in fires}
    quiet = evaluate_rules(packs, _scan())                  # has TLS 1.3 -> no fire
    assert "QER-RULE-NO-TLS13" not in {f.id for f in quiet}


def test_unreachable_scan_yields_no_rule_findings():
    packs, _ = load_rule_packs()
    assert evaluate_rules(packs, _scan(reachable=False)) == []


# --------------------------------------------------------------------------- #
# Loading / robustness
# --------------------------------------------------------------------------- #

def test_load_user_pack(tmp_path):
    pack = {"id": "p", "rules": [{"id": "R1", "title": "t",
            "match": {"scan": {"reachable": True}}, "severity": "low"}]}
    f = tmp_path / "p.json"
    f.write_text(json.dumps(pack), encoding="utf-8")
    packs, errs = load_rule_packs([str(f)])
    assert not errs
    assert any(p.id == "p" for p in packs)
    fires = evaluate_rules(packs, _scan())
    assert "R1" in {x.id for x in fires}


def test_malformed_rules_are_skipped(tmp_path):
    pack = {"id": "p", "rules": [
        {"id": "OK", "title": "t", "match": {"scan": {"reachable": True}}},
        {"id": "NOMATCH"},                                  # missing 'match' -> dropped
        "garbage",                                          # not a dict -> dropped
    ]}
    f = tmp_path / "p.json"
    f.write_text(json.dumps(pack), encoding="utf-8")
    p = load_pack(str(f))
    assert [r["id"] for r in p.rules] == ["OK"]


def test_bad_pack_is_reported_not_fatal(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("{ not valid json ", encoding="utf-8")
    packs, errs = load_rule_packs([str(f)])
    assert errs and any("bad.json" in e for e in errs)
    assert any(p.id == "qer-builtin" for p in packs)        # builtin still loaded


def test_not_a_pack_raises(tmp_path):
    f = tmp_path / "x.json"
    f.write_text(json.dumps({"id": "x"}), encoding="utf-8")  # no 'rules'
    with pytest.raises(RuleError):
        load_pack(str(f))


def test_dedupe_first_pack_wins():
    # two packs both defining R; evaluate keeps one finding for that id
    from qer.rules import RulePack
    rule = {"id": "DUP", "title": "t", "match": {"scan": {"reachable": True}}}
    packs = [RulePack(id="a", rules=[rule]), RulePack(id="b", rules=[rule])]
    fires = [f for f in evaluate_rules(packs, _scan()) if f.id == "DUP"]
    assert len(fires) == 1 and fires[0].rule == "a/DUP"


def test_builtin_pack_is_well_formed():
    p = load_rule_packs()[0][0]
    assert p.id == "qer-builtin" and len(p.rules) == len(BUILTIN_PACK["rules"])


# --------------------------------------------------------------------------- #
# Review-fix regressions
# --------------------------------------------------------------------------- #

def test_nonempty_treats_numeric_zero_as_present():
    assert _apply_op("d", "nonempty", True, {"d": 0}) is True      # 0 is a present value
    assert _apply_op("d", "nonempty", True, {"d": None}) is False
    assert _apply_op("d", "nonempty", True, {"d": ""}) is False


def test_in_operator_with_non_list_does_not_crash():
    assert _apply_op("k", "in", 5, {"k": "x"}) is False            # expected must be a list


def test_match_unknown_keys_flags_typos():
    assert match_unknown_keys({"primitiv": {"role": "cipher"}})    # typo -> reported
    assert match_unknown_keys({"all": [{"scan": {"reachable": True}}]}) == []


def test_load_pack_warns_on_unknown_match_key(tmp_path):
    pack = {"id": "p", "rules": [{"id": "R", "title": "t", "match": {"scn": {"reachable": True}}}]}
    f = tmp_path / "p.json"
    f.write_text(json.dumps(pack), encoding="utf-8")
    _packs, errs = load_rule_packs([str(f)])
    assert any("unknown key" in e for e in errs)
