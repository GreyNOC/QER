"""Declarative, extensible detection rules with confidence scoring.

QER's built-in findings are *hardcoded* high-confidence observations. This module
adds a second, **data-driven** detection layer: rule packs (JSON, or YAML when
PyYAML is present) matched against a normalized view of each endpoint's scan
facts. Defenders encode their own policy ("flag any CBC cipher", "RSA leaf on a
payments host is a finding") without touching Python, and every rule-derived
finding carries:

* a **confidence** (0..1) — heuristics need not pretend to be certainties, and
* a **provenance** (``pack/rule`` id) — so every alert is auditable.

The match language is deliberately tiny and eval-free: boolean ``all`` / ``any``
/ ``not`` over leaf conditions that test the top-level ``scan`` facts, or assert
that *some* ``primitive`` / ``certificate`` matches an object spec. Operators are
expressed as field-name suffixes (``algorithm_contains``, ``bits_lt``,
``supported_versions_has``, ...), keeping packs readable.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Optional

from .models import Finding, QuantumRisk, ScanResult, Severity

REF_NIST_PQC = "https://csrc.nist.gov/projects/post-quantum-cryptography"


class RuleError(Exception):
    """A rule pack could not be loaded or is structurally invalid."""


@dataclass
class RulePack:
    id: str
    rules: list = field(default_factory=list)
    source: str = ""


# --------------------------------------------------------------------------- #
# Built-in pack: a few useful detections NOT already emitted by the hardcoded
# path, each demonstrating the schema and a sub-1.0 confidence.
# --------------------------------------------------------------------------- #

BUILTIN_PACK = {
    "id": "qer-builtin",
    "version": "1.0",
    "rules": [
        {
            "id": "QER-RULE-CBC-MODE",
            "title": "CBC-mode cipher negotiated",
            "severity": "medium", "quantum_risk": "quantum-weakened",
            "category": "deprecated", "confidence": 0.85,
            "match": {"primitive": {"role": "cipher", "detail_contains": "cbc"}},
            "description": "The endpoint negotiated a CBC-mode cipher. CBC construction has a long history "
                           "of padding-oracle and timing issues (BEAST, Lucky13) and is not authenticated; "
                           "AEAD suites (GCM/ChaCha20-Poly1305) are strongly preferred.",
            "recommendation": "Prefer AEAD cipher suites (AES-GCM, ChaCha20-Poly1305) and disable CBC suites.",
            "references": ["https://www.rfc-editor.org/rfc/rfc7457"],
        },
        {
            "id": "QER-RULE-NO-TLS13",
            "title": "TLS 1.3 not supported (blocks hybrid PQ key exchange)",
            "severity": "low", "quantum_risk": "quantum-vulnerable",
            "category": "pqc", "confidence": 0.9,
            "match": {"all": [
                {"scan": {"reachable": True}},
                {"not": {"scan": {"supported_versions_has": "TLSv1.3"}}},
            ]},
            "description": "The endpoint does not offer TLS 1.3. TLS 1.3 is the prerequisite for hybrid "
                           "post-quantum key exchange (the key_share groups like X25519MLKEM768 exist only "
                           "in 1.3), so this endpoint cannot adopt PQ key exchange until 1.3 is enabled.",
            "recommendation": "Enable TLS 1.3 so a hybrid PQ key-exchange group can later be negotiated.",
            "references": [REF_NIST_PQC],
        },
    ],
}


# --------------------------------------------------------------------------- #
# Fact projection
# --------------------------------------------------------------------------- #

def facts_from_scan(scan: ScanResult) -> dict:
    """A flat, JSON-like projection of a ScanResult for rules to match against."""
    return {
        "host": scan.host, "port": scan.port, "reachable": scan.reachable,
        "negotiated_version": scan.negotiated_version,
        "negotiated_cipher": scan.negotiated_cipher,
        "key_exchange": scan.key_exchange, "authentication": scan.authentication,
        "forward_secret": scan.forward_secret,
        "supported_versions": list(scan.supported_versions),
        "weak_versions": list(scan.weak_versions),
        "pq_kex_negotiated": scan.pq_kex_negotiated, "pq_preferred": scan.pq_preferred,
        "pq_groups_supported": list(scan.pq_groups_supported),
        "starttls": scan.starttls, "dominant_risk": scan.dominant_risk().label,
        "primitives": [{
            "role": p.role, "algorithm": p.algorithm, "quantum_risk": p.quantum_risk.label,
            "detail": p.detail, "bits": p.bits, "forward_secret": p.forward_secret,
        } for p in scan.primitives],
        "certificates": [{
            "position": c.position, "public_key_algorithm": c.public_key_algorithm,
            "public_key_bits": c.public_key_bits, "signature_algorithm": c.signature_algorithm,
            "quantum_risk": c.quantum_risk.label, "days_to_expiry": c.days_to_expiry,
        } for c in scan.certificates],
    }


# --------------------------------------------------------------------------- #
# Match engine (eval-free)
# --------------------------------------------------------------------------- #

_SUFFIX_OPS = ("_contains", "_in", "_has", "_lt", "_gt", "_nonempty", "_exists")


def _ci(x: Any) -> Any:
    return x.lower() if isinstance(x, str) else x


def _apply_op(field: str, op: str, expected: Any, obj: dict) -> bool:
    value = obj.get(field)
    if op == "exists":
        return (value is not None) == bool(expected)
    if op == "nonempty":
        # "present and not an empty string/collection" — note 0/False ARE present.
        present = value not in (None, "", [], (), {})
        return present == bool(expected)
    if op == "contains":
        return value is not None and _ci(str(expected)) in _ci(str(value))
    if op == "in":                                    # value is one of the expected list
        if not isinstance(expected, (list, tuple)):
            return False
        return _ci(value) in [_ci(v) for v in expected]
    if op == "has":                                   # expected is IN the list-valued field
        return isinstance(value, (list, tuple)) and _ci(expected) in [_ci(v) for v in value]
    if op in ("lt", "gt"):
        try:
            v = float(value)
        except (TypeError, ValueError):
            return False
        return v < float(expected) if op == "lt" else v > float(expected)
    # default: equality (case-insensitive for strings)
    return _ci(value) == _ci(expected)


def _obj_match(spec: dict, obj: dict) -> bool:
    for key, expected in spec.items():
        op = "equals"
        field = key
        for suffix in _SUFFIX_OPS:
            if key.endswith(suffix):
                op, field = suffix[1:], key[: -len(suffix)]
                break
        if not _apply_op(field, op, expected, obj):
            return False
    return True


_MATCH_KEYS = {"all", "any", "not", "primitive", "certificate", "scan"}


def match_unknown_keys(cond: Any, path: str = "match") -> list[str]:
    """Walk a match expression and report keys that the engine will silently
    ignore (so a typo'd combinator/target doesn't quietly never fire)."""
    if not isinstance(cond, dict):
        return [f"{path}: condition must be an object"]
    out = [f"{path}: unknown key '{k}' (expected one of {sorted(_MATCH_KEYS)})"
           for k in cond if k not in _MATCH_KEYS]
    for k in ("all", "any"):
        if isinstance(cond.get(k), list):
            for i, c in enumerate(cond[k]):
                out += match_unknown_keys(c, f"{path}.{k}[{i}]")
    if "not" in cond:
        out += match_unknown_keys(cond["not"], f"{path}.not")
    return out


def _match_key(key: str, cond: dict, facts: dict) -> bool:
    if key == "all":
        return all(match(c, facts) for c in cond["all"])
    if key == "any":
        return any(match(c, facts) for c in cond["any"])
    if key == "not":
        return not match(cond["not"], facts)
    if key == "primitive":
        return any(_obj_match(cond["primitive"], p) for p in facts.get("primitives", []))
    if key == "certificate":
        return any(_obj_match(cond["certificate"], c) for c in facts.get("certificates", []))
    return _obj_match(cond["scan"], facts)          # key == "scan"


def match(cond: Any, facts: dict) -> bool:
    if not isinstance(cond, dict):
        return False
    # Every recognised key present must hold (implicit AND) — so a natural
    # {"scan": ..., "certificate": ...} means both, not just the first checked.
    # An empty / all-unknown condition never fires.
    present = [k for k in _MATCH_KEYS if k in cond]
    if not present:
        return False
    return all(_match_key(k, cond, facts) for k in present)


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

def _coerce_pack(data: dict, source: str) -> RulePack:
    if not isinstance(data, dict) or "rules" not in data:
        raise RuleError(f"{source}: not a rule pack (missing 'rules')")
    rules = data["rules"]
    if not isinstance(rules, list):
        raise RuleError(f"{source}: 'rules' must be a list")
    valid = []
    for r in rules:
        if isinstance(r, dict) and r.get("id") and r.get("title") and isinstance(r.get("match"), dict):
            valid.append(r)
    return RulePack(id=str(data.get("id", os.path.basename(source) or "pack")),
                    rules=valid, source=source)


def _parse_text(text: str, source: str) -> dict:
    if source.lower().endswith((".yaml", ".yml")):
        try:
            import yaml  # optional; only needed for YAML packs
        except ImportError as exc:
            raise RuleError(f"{source}: YAML rule packs require PyYAML (`pip install pyyaml`) "
                            f"or convert the pack to JSON") from exc
        return yaml.safe_load(text)
    return json.loads(text)


def load_pack(path: str) -> RulePack:
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            data = _parse_text(fh.read(), path)
    except (OSError, ValueError) as exc:
        raise RuleError(f"{path}: {exc}") from exc
    return _coerce_pack(data, path)


def load_rule_packs(paths: Optional[list[str]] = None, use_builtin: bool = True
                    ) -> tuple[list[RulePack], list[str]]:
    """Load the built-in pack plus any user packs (files or directories). Returns
    (packs, errors); a bad pack is reported, never fatal."""
    packs: list[RulePack] = []
    errors: list[str] = []
    if use_builtin:
        packs.append(_coerce_pack(BUILTIN_PACK, "<builtin>"))
    for p in (paths or []):
        files: list[str] = []
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                if name.lower().endswith((".json", ".yaml", ".yml")):
                    files.append(os.path.join(p, name))
        else:
            files.append(p)
        for f in files:
            try:
                pack = load_pack(f)
            except RuleError as exc:
                errors.append(str(exc))
                continue
            for rule in pack.rules:                  # warn on silently-ignored match keys
                for warning in match_unknown_keys(rule.get("match", {})):
                    errors.append(f"{pack.source} [{rule.get('id')}]: {warning}")
            packs.append(pack)
    return packs, errors


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #

def _rule_finding(pack: RulePack, rule: dict, scan: ScanResult) -> Finding:
    auto_evidence = (f"{scan.negotiated_version or '?'} {scan.negotiated_cipher or ''} "
                     f"kex={scan.key_exchange or '?'}").strip()
    return Finding(
        id=str(rule["id"]), title=str(rule["title"]),
        severity=Severity.from_label(rule.get("severity", "info")),
        quantum_risk=QuantumRisk.from_label(rule.get("quantum_risk", "quantum-vulnerable")),
        category=str(rule.get("category", "rule")), host=scan.host, port=scan.port,
        description=str(rule.get("description", "")),
        evidence=str(rule.get("evidence", auto_evidence)),
        recommendation=str(rule.get("recommendation", "")),
        references=list(rule.get("references", [])),
        confidence=float(rule.get("confidence", 1.0)),
        rule=f"{pack.id}/{rule['id']}")


def evaluate_rules(packs: list[RulePack], scan: ScanResult) -> list[Finding]:
    """Run every rule in every pack against one scan, returning the findings that
    matched (first occurrence of each finding id wins, so packs can't duplicate)."""
    if not scan.reachable:
        return []
    facts = facts_from_scan(scan)
    out: list[Finding] = []
    seen: set[str] = set()
    for pack in packs:
        for rule in pack.rules:
            rid = str(rule["id"])
            if rid in seen:
                continue
            try:
                fired = match(rule["match"], facts)
            except Exception:
                fired = False                         # a malformed rule never breaks a scan
            if fired:
                seen.add(rid)
                out.append(_rule_finding(pack, rule, scan))
    return out
