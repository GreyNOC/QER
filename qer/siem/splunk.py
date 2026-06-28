"""Splunk SPL searches and saved-search alert definitions.

Assumes QER's NDJSON findings feed (``qer export --format ndjson``) is ingested
as ``sourcetype="qer:finding"``. Field names match :func:`qer.siem.json_out.finding_events`.
"""

from __future__ import annotations

from typing import Optional

from ..models import EndpointReport

_HEADER = """\
# ============================================================================
# QER -> Splunk detection content
# Ingest QER findings with:  sourcetype = qer:finding  (NDJSON, one finding/event)
#   [qer:finding]
#   INDEXED_EXTRACTIONS = json
#   KV_MODE = none
# ============================================================================
"""

_SEARCHES = """\
# --- Migration backlog: highest HNDL exposure first -------------------------
index=* sourcetype="qer:finding" category=hndl (severity=high OR severity=critical)
| stats max(hndl_risk) AS hndl_risk
        values(negotiated_cipher) AS ciphers
        values(priority) AS priority
        latest(scanned_at) AS last_seen
        BY host port
| sort - hndl_risk

# --- Cryptographic downgrade alert (page-worthy) ----------------------------
index=* sourcetype="qer:finding" category=downgrade
| table scanned_at host port finding_id title severity evidence

# --- Deprecated TLS still in service ----------------------------------------
index=* sourcetype="qer:finding" (finding_id=QER-PROTO-LEGACY OR category=deprecated)
| stats values(title) AS issues latest(scanned_at) AS last_seen BY host port
| sort host
"""

_SAVEDSEARCHES = """\
# ---------------------------------------------------------------------------
# savedsearches.conf  (drop into $SPLUNK_HOME/etc/apps/qer/local/)
# ---------------------------------------------------------------------------
[QER - Cryptographic Downgrade Detected]
search = index=* sourcetype="qer:finding" category=downgrade | table scanned_at host port finding_id title evidence
dispatch.earliest_time = -24h
cron_schedule = */15 * * * *
enableSched = 1
alert.severity = 4
alert_type = number of events
alert_comparator = greater than
alert_threshold = 0
action.email = 1
description = Fires when QER detects a TLS/PQ downgrade against the recorded baseline.

[QER - Critical HNDL Exposure]
search = index=* sourcetype="qer:finding" category=hndl severity=critical | stats count BY host port priority
dispatch.earliest_time = -24h
cron_schedule = 0 * * * *
enableSched = 1
alert.severity = 3
alert_type = number of events
alert_comparator = greater than
alert_threshold = 0
description = Long-lived sensitive data over quantum-vulnerable key exchange.
"""


def to_splunk(reports: list[EndpointReport], meta: Optional[dict] = None) -> str:
    return f"{_HEADER}\n{_SEARCHES}\n{_SAVEDSEARCHES}"
