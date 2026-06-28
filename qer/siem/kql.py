"""Microsoft Sentinel / Log Analytics KQL detections.

Assumes QER's NDJSON findings feed is ingested into a custom table ``QER_CL``.
Log Analytics suffixes custom columns by type (``_s`` string, ``_d`` double,
``_b`` boolean), which is reflected below.
"""

from __future__ import annotations

from typing import Optional

from ..models import EndpointReport

_KQL = """\
// ===========================================================================
// QER -> Microsoft Sentinel (Log Analytics custom table QER_CL)
// Ingest the NDJSON findings feed: qer export --format ndjson
// ===========================================================================

// --- Migration backlog ranked by HNDL exposure -----------------------------
QER_CL
| where category_s == "hndl" and severity_s in ("high", "critical")
| summarize arg_max(TimeGenerated, *) by host_s, port_d, finding_id_s
| project TimeGenerated, host_s, port_d, hndl_risk_d, priority_s, negotiated_cipher_s, evidence_s
| order by hndl_risk_d desc

// --- Analytics rule: cryptographic downgrade (schedule every 15m) ----------
QER_CL
| where category_s == "downgrade"
| where TimeGenerated > ago(24h)
| project TimeGenerated, host_s, port_d, finding_id_s, title_s, severity_s, evidence_s
| extend AccountCustomEntity = host_s

// --- Deprecated TLS surface (RFC 8996) -------------------------------------
QER_CL
| where finding_id_s == "QER-PROTO-LEGACY" or category_s == "deprecated"
| summarize Issues = make_set(title_s), LastSeen = max(TimeGenerated) by host_s, port_d
| order by host_s asc

// --- Post-quantum readiness rollup (for dashboards) ------------------------
QER_CL
| summarize arg_max(TimeGenerated, *) by host_s, port_d
| summarize
    Endpoints = dcount(strcat(host_s, ":", tostring(port_d))),
    NowPriority = countif(priority_s == "NOW"),
    SoonPriority = countif(priority_s == "SOON"),
    AvgHNDL = round(avg(hndl_risk_d), 1)
"""


def to_kql(reports: list[EndpointReport], meta: Optional[dict] = None) -> str:
    return _KQL
