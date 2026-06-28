"""Canonical JSON output: a full nested report and a flat NDJSON findings feed.

The flat ``finding_events`` schema is the contract the Sigma/Splunk/KQL detection
content is written against — one event per finding, with the scan facts and
scores denormalised onto it so a SIEM can alert without joins.
"""

from __future__ import annotations

import json
from typing import Optional

from .. import __version__
from ..models import EndpointReport, to_serializable


def finding_events(reports: list[EndpointReport]) -> list[dict]:
    """Flatten reports into one denormalised dict per finding."""
    events: list[dict] = []
    for r in reports:
        scan, scores = r.scan, r.scores
        base = {
            "tool": "qer",
            "tool_version": __version__,
            "scanned_at": scan.scanned_at,
            "host": scan.host,
            "port": scan.port,
            "ip": scan.ip,
            "asset_label": r.profile.label,
            "negotiated_version": scan.negotiated_version,
            "negotiated_cipher": scan.negotiated_cipher,
            "key_exchange": scan.key_exchange,
            "forward_secret": scan.forward_secret,
            "risk_score": scores.risk_score if scores else None,
            "hndl_risk": scores.hndl_risk if scores else None,
            "priority": scores.priority if scores else None,
        }
        for f in r.findings:
            event = dict(base)
            event.update({
                "finding_id": f.id,
                "title": f.title,
                "severity": f.severity.label,
                "quantum_risk": f.quantum_risk.label,
                "category": f.category,
                "description": f.description,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
                "references": f.references,
            })
            events.append(event)
    return events


def report_to_dict(reports: list[EndpointReport], meta: Optional[dict] = None) -> dict:
    return {
        "tool": "qer",
        "tool_version": __version__,
        "meta": meta or {},
        "endpoints": [to_serializable(r) for r in reports],
    }


def to_json(reports: list[EndpointReport], meta: Optional[dict] = None) -> str:
    return json.dumps(report_to_dict(reports, meta), indent=2)


def to_ndjson(reports: list[EndpointReport], meta: Optional[dict] = None) -> str:
    return "\n".join(json.dumps(e) for e in finding_events(reports))


# --- code scan (qer.codescan.CodeReport) ----------------------------------- #

def code_finding_events(report) -> list[dict]:
    """Flatten a CodeReport into one denormalised dict per finding, schema-
    compatible with the network feed (same finding_id/severity/category keys)."""
    base = {"tool": "qer", "tool_version": __version__, "scan_type": "code",
            "root": report.root, "scanned_at": report.scanned_at}
    events = []
    for f in report.findings:
        e = dict(base)
        e.update({
            "finding_id": f.id, "title": f.title, "severity": f.severity.label,
            "quantum_risk": f.quantum_risk.label, "category": f.category,
            "location": f.location, "evidence": f.evidence,
            "recommendation": f.recommendation,
        })
        events.append(e)
    return events


def code_to_json(report, meta: Optional[dict] = None) -> str:
    return json.dumps({
        "tool": "qer", "tool_version": __version__, "scan_type": "code",
        "meta": meta or {}, "root": report.root,
        "files_scanned": report.files_scanned,
        "findings": [to_serializable(f) for f in report.findings],
    }, indent=2)


def code_to_ndjson(report, meta: Optional[dict] = None) -> str:
    return "\n".join(json.dumps(e) for e in code_finding_events(report))


# --- passive measurement (qer.passive.PassiveReport) ----------------------- #

def passive_finding_events(report) -> list[dict]:
    base = {"tool": "qer", "tool_version": __version__, "scan_type": "passive",
            "source": report.source, "scanned_at": report.scanned_at}
    events = []
    for f in report.findings:
        e = dict(base)
        e.update({
            "finding_id": f.id, "title": f.title, "severity": f.severity.label,
            "quantum_risk": f.quantum_risk.label, "category": f.category,
            "service": f.location, "evidence": f.evidence,
            "recommendation": f.recommendation,
        })
        events.append(e)
    return events


def passive_to_json(report, meta: Optional[dict] = None) -> str:
    return json.dumps({
        "tool": "qer", "tool_version": __version__, "scan_type": "passive",
        "meta": meta or {}, "source": report.source,
        "total_connections": report.total_connections,
        "parsed_records": report.parsed_records,
        "services": [{
            "service": s.service, "total": s.total, "pq": s.pq,
            "classical": s.classical, "none": s.none, "pq_pct": s.pq_pct,
            "curves": s.curves,
        } for s in report.services],
        "findings": [to_serializable(f) for f in report.findings],
    }, indent=2)


def passive_to_ndjson(report, meta: Optional[dict] = None) -> str:
    return "\n".join(json.dumps(e) for e in passive_finding_events(report))
