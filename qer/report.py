"""Human-facing console report and the executive migration map.

The migration map is the deliverable the spec asks for in plain words:
"replace these 12 systems first; these 30 can wait." It buckets endpoints into
remediation waves by urgency (risk_score) and, within a wave, surfaces quick
wins (high risk but low migration difficulty) first.
"""

from __future__ import annotations

from .models import EndpointReport, QuantumRisk, Severity

# ----------------------------- ANSI styling -------------------------------- #

_ANSI = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[31m", "yellow": "\033[33m", "green": "\033[32m",
    "cyan": "\033[36m", "magenta": "\033[35m", "grey": "\033[90m",
}

_SEV_STYLE = {
    Severity.CRITICAL: ("red", "CRIT"),
    Severity.HIGH: ("red", "HIGH"),
    Severity.MEDIUM: ("yellow", "MED "),
    Severity.LOW: ("cyan", "LOW "),
    Severity.INFO: ("grey", "INFO"),
}

_PRIORITY_STYLE = {
    "NOW": "red", "SOON": "yellow", "LATER": "cyan", "OK": "green",
    "UNREACHABLE": "grey",
}

QUICK_WIN_RISK = 45
QUICK_WIN_DIFFICULTY = 40


class _Painter:
    def __init__(self, color: bool):
        self.color = color

    def __call__(self, text: str, *styles: str) -> str:
        if not self.color:
            return text
        prefix = "".join(_ANSI.get(s, "") for s in styles)
        return f"{prefix}{text}{_ANSI['reset']}" if prefix else text


def _bar(value: int, width: int = 10) -> str:
    filled = round(value / 100 * width)
    return "█" * filled + "·" * (width - filled)


# ----------------------------- migration map ------------------------------- #

def migration_map(reports: list[EndpointReport]) -> list[dict]:
    """Structured migration map, sorted into remediation waves."""
    rows = []
    for r in reports:
        s = r.scores
        if not s:
            continue
        rows.append({
            "endpoint": f"{r.scan.host}:{r.scan.port}",
            "label": r.profile.label,
            "priority": s.priority,
            "risk_score": s.risk_score,
            "hndl_risk": s.hndl_risk,
            "migration_difficulty": s.migration_difficulty,
            "readiness": s.readiness,
            "quick_win": s.priority in ("NOW", "SOON")
                         and s.risk_score >= QUICK_WIN_RISK
                         and s.migration_difficulty <= QUICK_WIN_DIFFICULTY,
            "reachable": r.scan.reachable,
        })
    order = {"NOW": 0, "SOON": 1, "LATER": 2, "OK": 3, "UNREACHABLE": 4}
    rows.sort(key=lambda x: (order.get(x["priority"], 9),
                             -x["risk_score"], x["migration_difficulty"]))
    return rows


# ----------------------------- console report ------------------------------ #

def _endpoint_block(r: EndpointReport, paint: _Painter, min_sev: Severity) -> list[str]:
    scan, s = r.scan, r.scores
    lines = []
    name = paint(f"{scan.host}:{scan.port}", "bold")
    if not scan.reachable:
        lines.append(f"{paint('○', 'grey')} {name}  {paint('UNREACHABLE', 'grey')}")
        lines.append(f"    {paint(scan.error or 'no TLS handshake', 'grey')}")
        return lines

    pr = s.priority if s else "?"
    pr_col = _PRIORITY_STYLE.get(pr, "grey")
    dot = paint("●", pr_col)
    header_meta = paint(
        f"[{pr}]  risk {s.risk_score:>3}  hndl {s.hndl_risk:>3}  diff {s.migration_difficulty:>3}",
        pr_col)
    lines.append(f"{dot} {name}  {header_meta}")

    fs = "yes" if scan.forward_secret else paint("NO", "red") if scan.forward_secret is False else "?"
    lines.append(f"    {scan.negotiated_version}  {scan.negotiated_cipher}  "
                 f"kex={scan.key_exchange}  fs={fs}")
    if scan.pq_testable:
        if scan.pq_groups_supported:
            tag = "enforced" if scan.pq_preferred else "classical accepted"
            lines.append(f"    PQ kex: {paint(', '.join(scan.pq_groups_supported), 'green')} "
                         f"{paint('(' + tag + ')', 'green' if scan.pq_preferred else 'yellow')}")
        else:
            lines.append(f"    PQ kex: {paint('none (classical only)', 'yellow')}")
    if scan.weak_versions:
        lines.append(f"    {paint('legacy accepted: ' + ', '.join(scan.weak_versions), 'red')}")
    for c in scan.certificates:
        keyd = f"{c.public_key_algorithm}" + (f"-{c.public_key_bits}" if c.public_key_bits else "")
        curve = f" {c.public_key_curve}" if c.public_key_curve else ""
        extra = ""
        if c.position == "leaf" and c.days_to_expiry is not None:
            exp = f"expires {c.days_to_expiry}d"
            extra = "  " + (paint(exp, "red") if c.days_to_expiry < 30 else exp)
        risk_mark = paint(" ⚠", "red") if c.quantum_risk == QuantumRisk.BROKEN_NOW else ""
        lines.append(f"    cert[{c.position}]: {keyd}{curve}  sig={c.signature_algorithm}{extra}{risk_mark}")

    shown = [f for f in r.findings if f.severity >= min_sev]
    shown.sort(key=lambda f: f.severity, reverse=True)
    for f in shown:
        col, tag = _SEV_STYLE[f.severity]
        lines.append(f"      {paint(tag, col, 'bold')}  {paint(f.id, 'grey')}  {f.title}")
    return lines


def render_console(reports: list[EndpointReport], meta: dict | None = None,
                   color: bool = True, min_severity: Severity = Severity.INFO,
                   quiet: bool = False) -> str:
    paint = _Painter(color)
    meta = meta or {}
    out: list[str] = []

    title = paint("GreyNOC Quantum Exposure Radar", "bold", "magenta")
    out.append(f"{title}  {paint('v' + str(meta.get('tool_version', '')), 'grey')}")
    reachable = sum(1 for r in reports if r.scan.reachable)
    out.append(paint(
        f"Scanned {len(reports)} endpoint(s), {reachable} reachable"
        + (f"  |  OpenSSL {meta.get('openssl', '')}" if meta.get("openssl") else ""), "grey"))
    out.append("")

    if not quiet:
        out.append(paint("CRYPTOGRAPHIC BILL OF MATERIALS", "bold"))
        out.append(paint("─" * 64, "grey"))
        for r in reports:
            out.extend(_endpoint_block(r, paint, min_severity))
            out.append("")

    # Executive migration map
    rows = migration_map(reports)
    out.append(paint("EXECUTIVE MIGRATION MAP", "bold"))
    out.append(paint("─" * 64, "grey"))
    waves = [("NOW", "Wave 1 — migrate now"), ("SOON", "Wave 2 — soon"),
             ("LATER", "Wave 3 — later"), ("OK", "Defer — acceptable for now"),
             ("UNREACHABLE", "Unreachable")]
    for pr_key, label in waves:
        group = [x for x in rows if x["priority"] == pr_key]
        if not group:
            continue
        col = _PRIORITY_STYLE.get(pr_key, "grey")
        out.append(paint(f"{label} ({len(group)})", col, "bold"))
        for x in group:
            tag = paint(" ★ quick win", "green") if x["quick_win"] else ""
            name = x["endpoint"] + (f"  {paint(x['label'], 'grey')}" if x["label"] else "")
            if pr_key == "UNREACHABLE":
                out.append(f"  • {name}")
            else:
                out.append(f"  • {name}")
                out.append(paint(
                    f"      risk {_bar(x['risk_score'])} {x['risk_score']:>3}   "
                    f"hndl {x['hndl_risk']:>3}   diff {x['migration_difficulty']:>3}{tag}", "grey"))
        out.append("")

    # Summary counts
    sev_counts: dict[Severity, int] = {}
    for r in reports:
        for f in r.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    summary = "  ".join(
        f"{_SEV_STYLE[s][1].strip()}:{sev_counts.get(s, 0)}"
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO))
    out.append(paint("Findings  ", "bold") + summary)
    return "\n".join(out)


def _top_curves_line(s) -> str:
    items = sorted(s.curves.items(), key=lambda kv: -kv[1])[:3]
    return ", ".join(f"{c}:{n}" for c, n in items) if items else "no group negotiated"


def render_passive_console(report, meta: dict | None = None, color: bool = True,
                           min_severity: Severity = Severity.INFO) -> str:
    paint = _Painter(color)
    meta = meta or {}
    out: list[str] = []
    title = paint("GreyNOC Quantum Exposure Radar — passive PQ measurement", "bold", "magenta")
    out.append(f"{title}  {paint('v' + str(meta.get('tool_version', '')), 'grey')}")
    out.append(paint(f"Read {report.parsed_records} record(s), {report.total_connections} connection(s) "
                     f"from {report.source}", "grey"))
    out.append("")
    out.append(paint("POST-QUANTUM COVERAGE BY SERVICE", "bold"))
    out.append(paint("─" * 64, "grey"))
    if not report.services:
        out.append(paint("  (no services met the connection threshold)", "grey"))
    for s in report.services:
        col = "green" if s.pq_pct == 100 else "yellow" if s.pq_pct > 0 else "red"
        out.append(f"  {paint(f'{s.pq_pct:>3}% PQ', col, 'bold')}  {paint(_bar(s.pq_pct), col)}  {s.service}")
        detail = f"pq={s.pq} classical={s.classical} none={s.none} total={s.total}"
        out.append(paint(f"        {detail}   {_top_curves_line(s)}", "grey"))
    out.append("")

    shown = [f for f in report.findings if f.severity >= min_severity]
    if shown:
        out.append(paint("FINDINGS", "bold"))
        out.append(paint("─" * 64, "grey"))
        for f in sorted(shown, key=lambda x: -int(x.severity)):
            scol, tag = _SEV_STYLE[f.severity]
            out.append(f"  {paint(tag, scol, 'bold')}  {paint(f.location, 'cyan')}  {f.title}")
        out.append("")

    sev_counts: dict[Severity, int] = {}
    for f in report.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    summary = "  ".join(
        f"{_SEV_STYLE[s][1].strip()}:{sev_counts.get(s, 0)}"
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO))
    out.append(paint("Findings  ", "bold") + summary)
    return "\n".join(out)


_CATEGORY_TITLES = {
    "secret": "Hardcoded secrets",
    "code-weak": "Broken / legacy primitives",
    "code-asymmetric": "Quantum-vulnerable asymmetric crypto",
    "code-jwt": "JWT / JWS signing",
    "code-dependency": "Crypto dependencies",
    "code-inventory": "Crypto inventory",
    "code-pq": "Post-quantum (good)",
}


def render_code_console(report, meta: dict | None = None, color: bool = True,
                        min_severity: Severity = Severity.INFO) -> str:
    paint = _Painter(color)
    meta = meta or {}
    out: list[str] = []
    title = paint("GreyNOC Quantum Exposure Radar — code scan", "bold", "magenta")
    out.append(f"{title}  {paint('v' + str(meta.get('tool_version', '')), 'grey')}")
    out.append(paint(f"Scanned {report.files_scanned} file(s) under {report.root}", "grey"))
    out.append("")

    shown = [f for f in report.findings if f.severity >= min_severity]
    by_cat: dict[str, list] = {}
    for f in shown:
        by_cat.setdefault(f.category, []).append(f)

    order = ["secret", "code-weak", "code-jwt", "code-asymmetric", "code-dependency",
             "code-inventory", "code-pq"]
    for cat in order + [c for c in by_cat if c not in order]:
        group = by_cat.get(cat)
        if not group:
            continue
        out.append(paint(f"{_CATEGORY_TITLES.get(cat, cat)} ({len(group)})", "bold"))
        for f in sorted(group, key=lambda x: (-int(x.severity), x.location)):
            col, tag = _SEV_STYLE[f.severity]
            loc = paint(f.location, "cyan")
            out.append(f"  {paint(tag, col, 'bold')}  {f.title}")
            out.append(f"        {loc}  {paint(f.evidence[:88], 'grey')}")
        out.append("")

    sev_counts: dict[Severity, int] = {}
    for f in report.findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    summary = "  ".join(
        f"{_SEV_STYLE[s][1].strip()}:{sev_counts.get(s, 0)}"
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO))
    out.append(paint("Findings  ", "bold") + summary)
    return "\n".join(out)
