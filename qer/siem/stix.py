"""STIX 2.1 bundle exporter (for TAXII threat-intel sharing).

Turns QER's *actionable* exposures into a STIX 2.1 bundle a threat-intel
platform or SIEM can ingest over TAXII. The mapping:

* one ``identity`` SDO for the producer (QER) — referenced by ``created_by_ref``;
* one ``identity`` SDO (``identity_class: system``) per scanned asset that has at
  least one actionable finding;
* one ``vulnerability`` SDO per actionable finding (severity >= low), carrying
  the finding's text, ``external_references`` (NIST PQC etc. + the QER id), and
  ``x_qer_*`` custom properties (severity, quantum risk, category, host);
* one ``related-to`` ``relationship`` SRO linking each asset to its vulnerabilities.

Informational findings (PQ-supported, chain inventory) are intentionally omitted
— a TI feed shares exposures, not "all clear" notes; the full inventory lives in
the JSON / CycloneDX CBOM. IDs are deterministic (uuid5) so re-exports are stable.
"""

from __future__ import annotations

import datetime as dt
import json
import uuid
from typing import Optional

from .. import __version__
from ..models import EndpointReport, Severity

# Fixed namespace so the same scan always yields the same STIX ids.
_NS = uuid.UUID("b6f0a8e2-1c44-4f0a-9e21-2d5a4c0f1a00")
_QER_IDENTITY = "GreyNOC Quantum Exposure Radar"


def _sid(stype: str, key: str) -> str:
    return f"{stype}--{uuid.uuid5(_NS, stype + ':' + key)}"


_DEFAULT_TS = "2026-01-01T00:00:00.000Z"


def _stix_ts(meta: dict) -> str:
    """A valid STIX 2.1 timestamp: RFC 3339, converted to true UTC with a 'Z'.

    STIX requires UTC with the literal 'Z'; we parse the input and convert any
    offset to UTC rather than doing string surgery (which would emit invalid
    'offset+Z' values or falsely label naive times as UTC)."""
    t = str(meta.get("generated_at") or "").strip()
    if not t:
        return _DEFAULT_TS
    try:
        d = dt.datetime.fromisoformat(t)
    except ValueError:
        return _DEFAULT_TS
    d = d.replace(tzinfo=dt.timezone.utc) if d.tzinfo is None else d.astimezone(dt.timezone.utc)
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond // 1000:03d}Z"


def _prune(obj):
    if isinstance(obj, dict):
        return {k: _prune(v) for k, v in obj.items() if v is not None}
    if isinstance(obj, list):
        return [_prune(v) for v in obj]
    return obj


def to_stix(reports: list[EndpointReport], meta: Optional[dict] = None) -> str:
    meta = meta or {}
    ts = _stix_ts(meta)
    qer_id = _sid("identity", "qer-producer")

    objects: list[dict] = [{
        "type": "identity",
        "spec_version": "2.1",
        "id": qer_id,
        "created": ts,
        "modified": ts,
        "name": _QER_IDENTITY,
        "identity_class": "system",
        "description": f"QER {meta.get('tool_version', __version__)} — PQC exposure scanner.",
    }]

    for r in reports:
        scan = r.scan
        if not scan.reachable:
            continue
        actionable = [f for f in r.findings if f.severity >= Severity.LOW]
        if not actionable:
            continue
        host = f"{scan.host}:{scan.port}"
        asset_id = _sid("identity", host)
        objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": asset_id,
            "created": ts,
            "modified": ts,
            "created_by_ref": qer_id,
            "name": host,
            "identity_class": "system",
            "x_qer_negotiated_version": scan.negotiated_version,
            "x_qer_negotiated_cipher": scan.negotiated_cipher,
            "x_qer_priority": r.scores.priority if r.scores else None,
            "x_qer_hndl_risk": r.scores.hndl_risk if r.scores else None,
        })

        for f in actionable:
            ext_refs = [{"source_name": "qer", "external_id": f.id}]
            ext_refs += [{"source_name": "reference", "url": ref} for ref in f.references]
            vuln_id = _sid("vulnerability", host + "|" + f.id)
            objects.append({
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": vuln_id,
                "created": ts,
                "modified": ts,
                "created_by_ref": qer_id,
                "name": f.title or f.id,        # name is required; never emit empty
                "description": f.description,
                "labels": [f.quantum_risk.label, f.category],
                "external_references": ext_refs,
                "x_qer_severity": f.severity.label,
                "x_qer_quantum_risk": f.quantum_risk.label,
                "x_qer_category": f.category,
                "x_qer_host": host,
                "x_qer_evidence": f.evidence or None,
                "x_qer_recommendation": f.recommendation or None,
            })
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": _sid("relationship", host + "|" + f.id),
                "created": ts,
                "modified": ts,
                "created_by_ref": qer_id,
                "relationship_type": "related-to",
                "source_ref": asset_id,
                "target_ref": vuln_id,
            })

    key = ",".join(sorted(f"{r.scan.host}:{r.scan.port}" for r in reports)) or "empty"
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(_NS, 'bundle:' + key)}",
        "objects": _prune(objects),
    }
    return json.dumps(bundle, indent=2)
