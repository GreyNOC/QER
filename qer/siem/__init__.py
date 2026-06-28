"""SIEM and detection-content exporters.

``json_out`` is the canonical machine output: a full nested report plus a flat,
one-event-per-finding NDJSON feed. The other exporters emit *detection content*
for specific platforms:

* ``sigma``  — portable Sigma rules (over the QER findings feed and over Zeek ssl telemetry)
* ``splunk`` — SPL searches / alert definitions over the ``qer`` sourcetype
* ``kql``    — Microsoft Sentinel / Log Analytics KQL over a ``QER_CL`` custom table
* ``zeek``   — a Zeek script that flags quantum-vulnerable TLS on the wire in real time
"""

from . import cyclonedx, json_out, kql, sigma, splunk, zeek

EXPORTERS = {
    "json": json_out.to_json,
    "ndjson": json_out.to_ndjson,
    "cyclonedx": cyclonedx.to_cyclonedx,
    "sigma": sigma.to_sigma,
    "splunk": splunk.to_splunk,
    "kql": kql.to_kql,
    "zeek": zeek.to_zeek,
}

__all__ = ["json_out", "cyclonedx", "sigma", "splunk", "kql", "zeek", "EXPORTERS"]
