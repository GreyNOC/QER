"""Passive PQ measurement from Zeek ``ssl.log``.

Active probing (:mod:`qer.pqprobe`) tells you a server *supports* PQ. It cannot
tell you what fraction of *real* traffic actually negotiates it — that depends
on the live client population. This module reads a Zeek ``ssl.log`` (TSV or
JSON) and measures it: per service, the share of observed TLS connections whose
negotiated key-exchange group (the ``curve`` field) is post-quantum / hybrid.

That turns "PQ is supported" into a measured "PQ is protecting N% of traffic" —
and surfaces the legacy-client tail that is still harvest-now-decrypt-later
exposed even when the server itself is PQ-ready.
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field

from .classify import is_pq_algorithm
from .models import Finding, QuantumRisk, Severity

REF_NIST_PQC = "https://csrc.nist.gov/projects/post-quantum-cryptography"
_UNSET = {"", "-", "(empty)", "(unset)", "na", "n/a", "none", "null"}

# Zeek ssl.log column names we care about (TSV header / JSON keys).
_F_RESP_H = "id.resp_h"
_F_RESP_P = "id.resp_p"
_F_SNI = "server_name"
_F_CURVE = "curve"
_F_VERSION = "version"
_F_CIPHER = "cipher"
_F_QER_PQ = "qer_pq"      # optional column added by the QER Zeek script


@dataclass
class ServiceStats:
    service: str
    total: int = 0
    pq: int = 0
    classical: int = 0
    none: int = 0
    curves: dict = field(default_factory=dict)

    @property
    def negotiated(self) -> int:
        return self.pq + self.classical

    @property
    def pq_pct(self) -> int:
        return round(100 * self.pq / self.negotiated) if self.negotiated else 0


@dataclass
class PassiveReport:
    source: str
    total_connections: int = 0
    parsed_records: int = 0
    services: list = field(default_factory=list)      # list[ServiceStats]
    findings: list = field(default_factory=list)
    scanned_at: str = ""


# Zeek versions predating the PQ group-name tables log a negotiated hybrid group
# by its raw codepoint as "unknown-NNNN" (decimal). Translate the known hybrid
# codepoints so a fully-PQ service is not mis-measured as 0% PQ / all-HNDL.
# Decimal codepoints per the IANA TLS Supported Groups registry.
_ZEEK_UNKNOWN_GROUPS = {
    4587: "SecP256r1MLKEM768",
    4588: "X25519MLKEM768",
    4589: "SecP384r1MLKEM1024",
    25497: "X25519Kyber768Draft00",
    25498: "SecP256r1Kyber768Draft00",
}


def _resolve_curve(curve: str) -> str:
    """Map Zeek's raw ``unknown-NNNN`` group encoding to a known group name."""
    c = curve.strip()
    low = c.lower()
    if low.startswith("unknown-") or low.startswith("unknown_"):
        try:
            return _ZEEK_UNKNOWN_GROUPS.get(int(c.split("-")[-1].split("_")[-1]), c)
        except ValueError:
            return c
    return c


def classify_curve(curve: str) -> str:
    """Return 'pq', 'classical', or 'none' for a negotiated group name."""
    if not curve or curve.strip().lower() in _UNSET:
        return "none"
    return "pq" if is_pq_algorithm(_resolve_curve(curve)) else "classical"


def record_pq_kind(rec: dict) -> str:
    """Prefer the explicit ``qer_pq`` column emitted by the QER Zeek script
    (set only when a group was negotiated); otherwise classify the ``curve``.
    This keeps measurement correct even when operators drop the verbose curve
    field and rely on the boolean column."""
    flag = str(rec.get("qer_pq", "")).strip().lower()
    if flag in ("t", "true", "1"):
        return "pq"
    if flag in ("f", "false", "0"):
        return "classical"
    return classify_curve(rec.get("curve", ""))


# --------------------------------------------------------------------------- #
# Zeek ssl.log parsing (TSV and JSON)
# --------------------------------------------------------------------------- #

def _parse_tsv(lines: list[str]) -> list[dict]:
    sep = "\t"
    unset = "-"
    empty = "(empty)"
    fields: list[str] = []
    records: list[dict] = []
    for line in lines:
        if line.startswith("#"):
            parts = line.rstrip("\n").split(None, 1) if line.startswith("#separator") else None
            if line.startswith("#separator") and parts and len(parts) == 2:
                sep = parts[1].encode().decode("unicode_escape")
            elif line.startswith("#unset_field"):
                bits = line.rstrip("\n").split(sep)
                if len(bits) >= 2:
                    unset = bits[1]
            elif line.startswith("#empty_field"):
                bits = line.rstrip("\n").split(sep)
                if len(bits) >= 2:
                    empty = bits[1]
            elif line.startswith("#fields"):
                fields = line.rstrip("\n").split(sep)[1:]
            continue
        if not line.strip() or not fields:
            continue
        values = line.rstrip("\n").split(sep)
        rec = {f: ("" if v in (unset, empty) else v) for f, v in zip(fields, values)}
        records.append(rec)
    return records


def _parse_json(lines: list[str]) -> list[dict]:
    records = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def parse_ssl_log(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    first = next((l for l in lines if l.strip()), "")
    raw = _parse_json(lines) if first.lstrip().startswith("{") else _parse_tsv(lines)

    def _s(v):
        # None -> ""; preserve everything else (notably JSON booleans, so a
        # qer_pq value of False survives as "False" rather than collapsing to "").
        return "" if v is None else str(v)

    out = []
    for r in raw:
        # JSON pipelines (Filebeat/Logstash/ECS, json-streaming-logs) often nest
        # the connection 5-tuple under an "id" object instead of dotted keys.
        if isinstance(r.get("id"), dict):
            nid = r["id"]
            r.setdefault(_F_RESP_H, nid.get("resp_h"))
            r.setdefault(_F_RESP_P, nid.get("resp_p"))
        out.append({
            "server_name": _s(r.get(_F_SNI)),
            "resp_h": _s(r.get(_F_RESP_H)),
            "resp_p": _s(r.get(_F_RESP_P)),
            "version": _s(r.get(_F_VERSION)),
            "cipher": _s(r.get(_F_CIPHER)),
            "curve": _s(r.get(_F_CURVE)),
            "qer_pq": _s(r.get(_F_QER_PQ)),
        })
    return out


# --------------------------------------------------------------------------- #
# Aggregation + findings
# --------------------------------------------------------------------------- #

def _service_key(rec: dict) -> str:
    sni = rec["server_name"].strip()
    if sni and sni.lower() not in _UNSET:
        return sni
    host = rec["resp_h"].strip() or "unknown"
    port = rec["resp_p"].strip()
    return f"{host}:{port}" if port else host


def aggregate(records: list[dict], source: str, min_connections: int = 1) -> PassiveReport:
    report = PassiveReport(source=source, parsed_records=len(records),
                           scanned_at=dt.datetime.now(dt.timezone.utc).isoformat())
    stats: dict[str, ServiceStats] = {}
    for rec in records:
        key = _service_key(rec)
        s = stats.setdefault(key, ServiceStats(service=key))
        s.total += 1
        kind = record_pq_kind(rec)
        setattr(s, kind, getattr(s, kind) + 1)
        if kind != "none" and rec["curve"]:
            s.curves[rec["curve"]] = s.curves.get(rec["curve"], 0) + 1

    report.total_connections = sum(s.total for s in stats.values())
    services = [s for s in stats.values() if s.total >= min_connections]
    # Most-exposed first: highest classical share, then most traffic.
    services.sort(key=lambda s: (-(s.classical), -s.total))
    report.services = services
    report.findings = _findings(services)
    return report


def _findings(services: list) -> list:
    out = []
    for s in services:
        if s.negotiated == 0:
            continue
        if s.pq == 0:
            out.append(Finding(
                id="QER-PASSIVE-CLASSICAL",
                title=f"0% post-quantum: all {s.negotiated} observed key exchanges are classical",
                severity=Severity.MEDIUM, quantum_risk=QuantumRisk.QUANTUM_VULNERABLE,
                category="hndl", host="(passive)", port=0, location=s.service,
                description="No observed TLS connection to this service negotiated a post-quantum / hybrid "
                            "group. All recorded traffic is harvest-now-decrypt-later exposed.",
                evidence=f"pq=0 classical={s.classical} of {s.total} connections; curves={_top_curves(s)}",
                recommendation="Enable a hybrid group server-side and drive clients to advertise it.",
                references=[REF_NIST_PQC]))
        elif s.classical > 0:
            out.append(Finding(
                id="QER-PASSIVE-PARTIAL",
                title=f"{s.pq_pct}% post-quantum: {s.classical} of {s.negotiated} key exchanges still classical",
                severity=Severity.LOW, quantum_risk=QuantumRisk.QUANTUM_VULNERABLE,
                category="hndl", host="(passive)", port=0, location=s.service,
                description="Some traffic negotiates PQ but a classical-client tail remains and is "
                            "harvest-now-decrypt-later exposed.",
                evidence=f"pq={s.pq} classical={s.classical} ({s.pq_pct}% PQ); curves={_top_curves(s)}",
                recommendation="Identify and upgrade the classical clients; consider enforcing the hybrid group.",
                references=[REF_NIST_PQC]))
        else:
            out.append(Finding(
                id="QER-PASSIVE-PQ-OK",
                title=f"100% post-quantum across {s.negotiated} observed key exchanges",
                severity=Severity.INFO, quantum_risk=QuantumRisk.PQ_SAFE,
                category="pqc", host="(passive)", port=0, location=s.service,
                description="Every observed key exchange to this service negotiated a post-quantum / hybrid group.",
                evidence=f"pq={s.pq} of {s.negotiated}; curves={_top_curves(s)}",
                recommendation="Maintain; monitor for regressions.",
                references=[REF_NIST_PQC]))
    return out


def _top_curves(s: ServiceStats) -> str:
    items = sorted(s.curves.items(), key=lambda kv: -kv[1])[:3]
    return ", ".join(f"{c}:{n}" for c, n in items) or "-"


def measure(path: str, min_connections: int = 1) -> PassiveReport:
    return aggregate(parse_ssl_log(path), source=path, min_connections=min_connections)
