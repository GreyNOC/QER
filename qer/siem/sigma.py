"""Sigma detection rules.

Two logsource flavours are produced:

* ``product: qer`` rules fire on QER's own findings feed once it is shipped to
  the SIEM (one NDJSON event per finding — see :mod:`qer.siem.json_out`).
* a ``product: zeek`` rule fires on native Zeek ``ssl`` telemetry, so weak-TLS
  detection works even where QER has not actively scanned.

Rules are emitted as a multi-document YAML stream and only included when the
corresponding finding category is present in the scan (the Zeek rule is always
included as standing network coverage).
"""

from __future__ import annotations

import datetime as dt
from typing import Optional

from ..models import EndpointReport

AUTHOR = "GreyNOC QER"

# Stable UUIDs so re-exporting a rule updates rather than duplicates it in a SIEM.
_IDS = {
    "hndl": "b6f0a8e2-1c44-4f0a-9e21-2d5a4c0f1a01",
    "downgrade": "b6f0a8e2-1c44-4f0a-9e21-2d5a4c0f1a02",
    "deprecated": "b6f0a8e2-1c44-4f0a-9e21-2d5a4c0f1a03",
    "pqc": "b6f0a8e2-1c44-4f0a-9e21-2d5a4c0f1a04",
    "zeek_weak_tls": "b6f0a8e2-1c44-4f0a-9e21-2d5a4c0f1a05",
}


def _qer_rule(title, rule_id, description, category, level, tags, refs) -> str:
    ref_block = "\n".join(f"    - {r}" for r in refs) or "    - https://github.com/GreyNOC/QER"
    tag_block = "\n".join(f"    - {t}" for t in tags)
    date = dt.date.today().strftime("%Y/%m/%d")
    return f"""title: {title}
id: {rule_id}
status: experimental
description: {description}
references:
{ref_block}
author: {AUTHOR}
date: {date}
logsource:
  product: qer
  service: findings
detection:
  selection:
    tool: qer
    category: '{category}'
  high_severity:
    severity:
      - high
      - critical
  condition: selection and high_severity
fields:
  - host
  - port
  - finding_id
  - hndl_risk
  - priority
  - evidence
falsepositives:
  - Assets intentionally accepted into the post-quantum migration backlog
level: {level}
tags:
{tag_block}"""


def _zeek_weak_tls_rule() -> str:
    date = dt.date.today().strftime("%Y/%m/%d")
    return f"""title: Weak TLS Version Negotiated (Zeek)
id: {_IDS['zeek_weak_tls']}
status: experimental
description: A TLS session negotiated a version deprecated by RFC 8996 (TLS 1.1 or below).
references:
    - https://www.rfc-editor.org/rfc/rfc8996
author: {AUTHOR}
date: {date}
logsource:
  product: zeek
  service: ssl
detection:
  selection:
    version:
      - SSLv3
      - TLSv10
      - TLSv11
  condition: selection
fields:
  - id.resp_h
  - id.resp_p
  - server_name
  - version
  - cipher
falsepositives:
  - Legacy internal systems pending decommission
level: high
tags:
  - attack.t1562
  - attack.defense_evasion"""


def to_sigma(reports: list[EndpointReport], meta: Optional[dict] = None) -> str:
    categories = {f.category for r in reports for f in r.findings}
    docs: list[str] = []

    if "hndl" in categories:
        docs.append(_qer_rule(
            "QER - Harvest-Now-Decrypt-Later Exposure", _IDS["hndl"],
            "Endpoint protects long-lived sensitive data with quantum-vulnerable key exchange.",
            "hndl", "high",
            ["attack.t1040", "attack.collection"],
            ["https://csrc.nist.gov/projects/post-quantum-cryptography"]))
    if "downgrade" in categories:
        docs.append(_qer_rule(
            "QER - Cryptographic Downgrade Detected", _IDS["downgrade"],
            "Endpoint crypto posture regressed (TLS version, forward secrecy, or PQ key exchange).",
            "downgrade", "high",
            ["attack.t1557", "attack.t1562", "attack.credential_access"],
            ["https://www.rfc-editor.org/rfc/rfc8996"]))
    if "deprecated" in categories:
        docs.append(_qer_rule(
            "QER - Deprecated Cryptography In Use", _IDS["deprecated"],
            "Endpoint accepts deprecated/broken protocols or ciphers (TLS<=1.1, RC4, 3DES, SHA-1).",
            "deprecated", "medium",
            ["attack.t1562", "attack.defense_evasion"],
            ["https://www.rfc-editor.org/rfc/rfc8996"]))
    if "pqc" in categories:
        docs.append(_qer_rule(
            "QER - Quantum-Vulnerable Certificate Or Cipher", _IDS["pqc"],
            "Endpoint relies on RSA/ECC certificates or 128-bit symmetric crypto for long-lived data.",
            "pqc", "medium",
            ["attack.t1040"],
            ["https://csrc.nist.gov/projects/post-quantum-cryptography"]))

    docs.append(_zeek_weak_tls_rule())   # always-on network coverage
    return "\n---\n".join(docs) + "\n"
