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
        f"[{pr}]  risk {s.risk_score:>3}  hndl {s.hndl_risk:>3}  diff {s.migration_difficulty:>3}"
        if s else f"[{pr}]", pr_col)            # reachable but unscored -> facts only, no crash
    lines.append(f"{dot} {name}  {header_meta}")

    fs = "yes" if scan.forward_secret else paint("NO", "red") if scan.forward_secret is False else "?"
    via = paint(f"  via STARTTLS({scan.starttls})", "cyan") if scan.starttls else ""
    lines.append(f"    {scan.negotiated_version}  {scan.negotiated_cipher}  "
                 f"kex={scan.key_exchange}  fs={fs}{via}")
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
        conf = paint(f"  ~{f.confidence:.0%}", "grey") if f.confidence < 1.0 else ""
        lines.append(f"      {paint(tag, col, 'bold')}  {paint(f.id, 'grey')}  {f.title}{conf}")
    return lines


def _horizon_panel(horizon_assets, paint: _Painter) -> list[str]:
    """Executive 'how exposed are we, in years' panel (Mosca horizon)."""
    from .horizon import fleet_horizon
    out: list[str] = []
    fleet = fleet_horizon(horizon_assets)
    out.append(paint("QUANTUM EXPOSURE HORIZON", "bold"))
    out.append(paint("─" * 64, "grey"))
    out.append(paint(f"scenario: {fleet.scenario} (CRQC ~{fleet.crqc_year})   "
                     f"{fleet.exposed}/{fleet.hndl_relevant} HNDL endpoints already exposed", "grey"))
    exposed = sorted((h for h in horizon_assets if h.verdict == "exposed"),
                     key=lambda h: -h.exposure_years)
    for h in exposed:
        col = "red" if h.exposure_years >= 7 else "yellow" if h.exposure_years >= 3 else "cyan"
        out.append(f"  {paint('▲', col)} {h.host}:{h.port}  "
                   + paint(f"+{h.exposure_years:g}y overhang", col, "bold")
                   + paint(f"   shelf {h.shelf_life_years}y + migrate {h.migration_years:g}y "
                           f"vs {h.years_to_crqc:g}y to CRQC   start-by {h.start_by_year}", "grey"))
    if not exposed:
        out.append(paint("  no endpoints have data outliving the quantum horizon under this scenario.", "green"))
    elif fleet.earliest_start_by_year is not None:
        out.append("")
        out.append(paint(f"  earliest migration start-by date across the fleet: {fleet.earliest_start_by_year}"
                         + (f"  (already {abs(fleet.worst_shortfall_years):g}y past for the worst asset)"
                            if fleet.worst_shortfall_years > 0 else ""), "bold"))
    out.append("")
    return out


def render_console(reports: list[EndpointReport], meta: dict | None = None,
                   color: bool = True, min_severity: Severity = Severity.INFO,
                   quiet: bool = False, horizon_assets=None) -> str:
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

    # Quantum exposure horizon (Mosca) — years of overhang, the executive metric.
    if horizon_assets:
        out.extend(_horizon_panel(horizon_assets, paint))

    # Summary counts
    sev_counts: dict[Severity, int] = {}
    for r in reports:
        for f in r.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    summary = "  ".join(
        f"{_SEV_STYLE[s][1].strip()}:{sev_counts.get(s, 0)}"
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO))

    # Fleet PQ posture — most useful for a sweep of many endpoints.
    if len(reports) > 1:
        reachable = sum(1 for r in reports if r.scan.reachable)
        pq_capable = sum(1 for r in reports if r.scan.pq_groups_supported)
        pq_enforce = sum(1 for r in reports if r.scan.pq_preferred)
        exposed = sum(1 for h in (horizon_assets or []) if getattr(h, "verdict", "") == "exposed")
        pct = round(100 * pq_capable / reachable) if reachable else 0
        out.append(paint("Fleet     ", "bold")
                   + paint(f"{reachable} reachable   {pq_capable} PQ-capable ({pct}%)   "
                           f"{pq_enforce} PQ-enforced   {exposed} HNDL-exposed", "grey"))
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


_IKE_RISK_COLOR = {"broken-now": "red", "quantum-vulnerable": "yellow",
                   "quantum-weakened": "yellow", "pq-safe": "green"}


def render_ike_console(result, meta: dict | None = None, color: bool = True) -> str:
    paint = _Painter(color)
    meta = meta or {}
    out: list[str] = []
    title = paint("GreyNOC Quantum Exposure Radar — IKE / IPsec scan", "bold", "magenta")
    out.append(f"{title}  {paint('v' + str(meta.get('tool_version', '')), 'grey')}")
    out.append(paint(f"{result.host}:{result.port}/udp", "bold"))
    out.append(paint("note: IKE scanning is unit-verified, not live-proven — treat as best-effort.", "grey"))
    out.append("")
    if not result.reachable:
        out.append(f"  {paint('no IKE response', 'grey')}  {result.error or ''}")
        return "\n".join(out)

    out.append(f"  IKEv{result.ike_version}   responder={result.responder}")
    if result.chosen:
        out.append(paint("  Negotiated transforms", "bold"))
        for role in ("encryption", "prf", "integrity", "dh-group"):
            info = result.chosen.get(role)
            if not info:
                continue
            algo = info["name"] + (f"-{info['keylen']}" if info.get("keylen") else "")
            rl = info.get("quantum_risk", "")
            out.append(f"    {role:12} {algo:26} {paint(rl, _IKE_RISK_COLOR.get(rl, 'grey'))}")
    if result.invalid_ke_group is not None:
        out.append(f"    {paint('gateway requested DH group ' + str(result.invalid_ke_group), 'yellow')}")
    out.append("")
    if result.findings:
        out.append(paint("  Findings", "bold"))
        for f in sorted(result.findings, key=lambda x: -int(x.severity)):
            scol, tag = _SEV_STYLE[f.severity]
            out.append(f"    {paint(tag, scol, 'bold')}  {paint(f.id, 'grey')}  {f.title}")
    return "\n".join(out)


_SSH_RISK_COLOR = {"broken-now": "red", "quantum-vulnerable": "yellow",
                   "quantum-weakened": "yellow", "pq-safe": "green"}


def render_ssh_console(result, meta: dict | None = None, color: bool = True) -> str:
    paint = _Painter(color)
    meta = meta or {}
    out: list[str] = []
    title = paint("GreyNOC Quantum Exposure Radar — SSH scan", "bold", "magenta")
    out.append(f"{title}  {paint('v' + str(meta.get('tool_version', '')), 'grey')}")
    out.append(paint(f"{result.host}:{result.port}/tcp", "bold")
               + (f"   {paint(result.software or result.banner or '', 'grey')}"))
    out.append("")
    if not result.reachable:
        out.append(f"  {paint('no SSH response', 'grey')}  {result.error or ''}")
        return "\n".join(out)

    # Reachable, but the banner read succeeded while the KEXINIT read/parse did
    # not (timeout, non-SSH service, hostile dribble): we have no algorithm lists,
    # so don't render a confident "no PQ key exchange" verdict off empty data.
    if not result.kex_algorithms:
        out.append(f"  {paint('scan incomplete', 'yellow', 'bold')}  "
                   f"{result.error or 'no KEXINIT received after banner'}")
        return "\n".join(out)

    # PQ verdict banner
    if result.pq_kex_preferred:
        out.append("  " + paint(f"● post-quantum key exchange PREFERRED ({result.preferred_kex})", "green", "bold"))
    elif result.pq_kex_offered:
        out.append("  " + paint(f"● post-quantum key exchange offered but not preferred "
                                 f"(prefers {result.preferred_kex})", "yellow", "bold"))
    else:
        out.append("  " + paint(f"● no post-quantum key exchange (prefers {result.preferred_kex})", "red", "bold"))
    out.append("")

    rows = (("key exchange", result.kex_algorithms, _classify_kex_risk),
            ("host keys", result.host_key_algorithms, _classify_hostkey_risk),
            ("ciphers", result.ciphers, _classify_cipher_risk),
            ("MACs", result.macs, _classify_mac_risk))
    out.append(paint("  Offered algorithms (preference order)", "bold"))
    for label, items, riskfn in rows:
        if not items:
            continue
        out.append(f"    {paint(label + ':', 'bold')}")
        for name in items:
            rl = riskfn(name)
            mark = paint(rl, _SSH_RISK_COLOR.get(rl, "grey")) if rl else paint("signalling", "grey")
            out.append(f"      {name:42} {mark}")
    out.append("")

    if result.findings:
        out.append(paint("  Findings", "bold"))
        for f in sorted(result.findings, key=lambda x: -int(x.severity)):
            scol, tag = _SEV_STYLE[f.severity]
            out.append(f"    {paint(tag, scol, 'bold')}  {paint(f.id, 'grey')}  {f.title}")
    return "\n".join(out)


# Small risk-label helpers for the SSH renderer (kept here so report.py stays the
# single place that knows how to colour a scan; sshscan.py owns the logic).
def _classify_kex_risk(name: str) -> str:
    from .sshscan import _is_real_kex, classify_kex
    return classify_kex(name)[0].label if _is_real_kex(name) else ""


def _classify_hostkey_risk(name: str) -> str:
    from .sshscan import classify_hostkey
    return classify_hostkey(name)[0].label


def _classify_cipher_risk(name: str) -> str:
    from .sshscan import classify_cipher
    return classify_cipher(name)[0].label


def _classify_mac_risk(name: str) -> str:
    from .sshscan import classify_mac
    return classify_mac(name)[0].label


_CATEGORY_TITLES = {
    "secret": "Hardcoded secrets",
    "code-weak": "Broken / legacy primitives",
    "code-asymmetric": "Quantum-vulnerable asymmetric crypto",
    "code-jwt": "JWT / JWS signing",
    "code-saml": "SAML / XML-DSig signing",
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

    order = ["secret", "code-weak", "code-jwt", "code-saml", "code-asymmetric",
             "code-dependency", "code-inventory", "code-pq"]
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
