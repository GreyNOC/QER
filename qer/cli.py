"""Command-line interface for QER.

    qer scan github.com cloudflare.com:443
    qer scan -f targets.txt --baseline .qer_baseline.json --update-baseline \\
             --out-dir out --format json,ndjson,sigma,splunk,kql,zeek
    qer scan -f targets.json --fail-on high        # CI gate
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import os
import ssl
import sys
from typing import Optional

from . import __version__
from .codescan import scan_path
from .downgrade import build_baseline, diff_reports, load_baseline, save_baseline
from .horizon import assess as assess_horizon
from .horizon import fleet_horizon, horizon_finding, to_serializable_fleet
from .ikescan import scan_ike
from .models import (AssetProfile, EndpointReport, Severity,
                     reports_from_document, to_serializable)
from .passive import measure
from .report import (render_code_console, render_console, render_ike_console,
                     render_passive_console, render_ssh_console)
from .rules import evaluate_rules, load_rule_packs
from .scanner import discover_services, scan_targets
from .scoring import _kex_hndl_factor, generate_findings, score_endpoint
from .siem import EXPORTERS, cyclonedx, json_out
from .sshscan import scan_ssh
from .targets import load_targets, profiles_from_args

_EXPORT_FILENAMES = {
    "json": "qer-report.json",
    "ndjson": "qer-findings.ndjson",
    "cyclonedx": "qer-cbom.cdx.json",
    "stix": "qer-stix.bundle.json",
    "html": "qer-radar.html",
    "sigma": "qer-rules.sigma.yml",
    "splunk": "qer-splunk.spl",
    "kql": "qer-sentinel.kql",
    "zeek": "qer-quantum-radar.zeek",
}

_SEVERITY_BY_NAME = {s.label: s for s in Severity}

# Default ports for `--discover`: TLS-native and STARTTLS-capable services.
DEFAULT_DISCOVERY_PORTS = [443, 8443, 9443, 993, 995, 465, 587, 25, 143, 110,
                           389, 636, 5432, 3306, 990]


def _parse_ports(spec: str) -> list[int]:
    """Parse '443,8443,8000-8002' into a de-duplicated, ordered port list."""
    ports: list[int] = []
    for tok in spec.split(","):
        tok = tok.strip()
        if not tok:
            continue
        if "-" in tok:
            lo, _, hi = tok.partition("-")
            ports.extend(range(int(lo), int(hi) + 1))
        else:
            ports.append(int(tok))
    seen, out = set(), []
    for p in ports:
        if 0 < p < 65536 and p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _enable_windows_ansi() -> None:  # pragma: no cover - platform specific
    if os.name != "nt":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


def _want_color(no_color: bool) -> bool:
    if no_color or os.environ.get("NO_COLOR") is not None:
        return False
    if not sys.stdout.isatty():
        return False
    _enable_windows_ansi()
    return True


def _write_text(path: str, content: str) -> None:
    """Write text to a path (creating parents) and note it on stderr."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    print(f"wrote {path}", file=sys.stderr)


def build_reports(profiles, timeout: float, enumerate_versions: bool,
                  workers: int, baseline_path: Optional[str], update_baseline: bool,
                  do_pq_probe: bool = True, pq_groups=None, do_chain: bool = True,
                  progress=None, horizon_scenario: Optional[str] = None,
                  crqc_year: Optional[int] = None, rule_paths: Optional[list] = None,
                  use_builtin_rules: bool = True
                  ) -> tuple[list[EndpointReport], dict, list]:
    scans = scan_targets(profiles, timeout=timeout,
                         enumerate_versions=enumerate_versions,
                         workers=workers, do_pq_probe=do_pq_probe,
                         pq_groups=pq_groups, do_chain=do_chain, progress=progress)
    by_key = {(s.host, s.port): s for s in scans}

    rule_packs, rule_errors = load_rule_packs(rule_paths, use_builtin=use_builtin_rules)
    for err in rule_errors:
        print(f"warning: rule pack skipped: {err}", file=sys.stderr)

    now = dt.datetime.now(dt.timezone.utc)
    reports: list[EndpointReport] = []
    horizons: list = []
    for p in profiles:
        scan = by_key.get((p.host, p.port))
        if scan is None:
            continue
        scores = score_endpoint(p, scan)
        findings = generate_findings(p, scan, scores)
        # Quantum exposure horizon (Mosca): years of overhang for this endpoint.
        hndl_relevant = scan.reachable and _kex_hndl_factor(scan) > 0
        h = assess_horizon(p, hndl_relevant, now.year, horizon_scenario, crqc_year)
        horizons.append(h)
        hf = horizon_finding(h)
        if hf:
            findings.append(hf)
        # Declarative rule engine: append rule findings not already present.
        existing = {f.id for f in findings}
        findings.extend(rf for rf in evaluate_rules(rule_packs, scan) if rf.id not in existing)
        reports.append(EndpointReport(profile=p, scan=scan, findings=findings, scores=scores))

    # Downgrade monitor: diff against an existing baseline before updating it.
    if baseline_path:
        baseline = load_baseline(baseline_path)
        if baseline:
            diff_reports(reports, baseline)
        if update_baseline or baseline is None:
            save_baseline(build_baseline(reports), baseline_path)

    fleet = fleet_horizon(horizons)
    meta = {
        "tool_version": __version__,
        "generated_at": now.isoformat(),
        "openssl": ssl.OPENSSL_VERSION,
        "endpoints": len(reports),
        "reachable": sum(1 for r in reports if r.scan.reachable),
        "horizon": to_serializable_fleet(fleet),
    }
    return reports, meta, horizons


def _write_export(fmt: str, reports, meta, out_dir: str) -> str:
    content = EXPORTERS[fmt](reports, meta)
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, _EXPORT_FILENAMES[fmt])
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def _cmd_scan(args) -> int:
    profiles = []
    if args.file:
        try:
            profiles.extend(load_targets(args.file))
        except (OSError, ValueError) as exc:
            print(f"error: could not load targets from {args.file}: {exc}", file=sys.stderr)
            return 1
    profiles.extend(profiles_from_args(args.hosts))

    if not profiles:
        print("error: no targets. Pass hosts positionally or use -f/--file.", file=sys.stderr)
        return 1

    if args.starttls:                       # explicit flag overrides per-target inference
        for p in profiles:
            p.starttls = args.starttls

    # Discovery sweep: connect-scan the seed hosts across a port set and keep only
    # the open services to deep-scan. Turns a CIDR into a live-services inventory.
    if args.discover:
        try:
            ports = _parse_ports(args.ports) if args.ports else DEFAULT_DISCOVERY_PORTS
        except ValueError:
            print(f"error: bad --ports value: {args.ports}", file=sys.stderr)
            return 1
        hosts = list(dict.fromkeys(p.host for p in profiles))
        if not args.quiet:
            print(f"discovering open services on {len(hosts)} host(s) × {len(ports)} port(s)...",
                  file=sys.stderr)
        open_pairs = discover_services(hosts, ports, timeout=args.discover_timeout,
                                       workers=max(args.workers, 64))
        if not open_pairs:
            print("no open services discovered.", file=sys.stderr)
            return 1
        if not args.quiet:
            print(f"discovered {len(open_pairs)} open service(s) on {len(hosts)} host(s); deep-scanning...",
                  file=sys.stderr)
        # Carry the business context (sensitivity, shelf_life, exposure, ...) from
        # the seed targets onto each discovered service: prefer an exact host:port
        # profile, else fall back to a same-host profile (e.g. annotations that sat
        # on a CIDR/host line), else a bare default profile.
        by_hostport = {(p.host, p.port): p for p in profiles}
        by_host = {p.host: p for p in profiles}
        discovered = []
        for (h, pt) in open_pairs:
            seed = by_hostport.get((h, pt)) or by_host.get(h)
            if seed is not None:
                discovered.append(dataclasses.replace(
                    seed, host=h, port=pt,
                    starttls=args.starttls or seed.starttls))
            else:
                discovered.append(AssetProfile(host=h, port=pt, starttls=args.starttls))
        profiles = discovered

    def progress(profile, result):
        if args.quiet:
            return
        status = result.negotiated_version or (result.error or "unreachable")
        print(f"  scanned {profile.host}:{profile.port:<5}  {status}", file=sys.stderr)

    pq_groups = None
    if args.pq_groups:
        from .pqprobe import PQ_GROUPS
        canon = {g.lower(): g for g in PQ_GROUPS}
        pq_groups, unknown = [], []
        for raw in args.pq_groups.split(","):
            name = raw.strip()
            if not name:
                continue
            match = canon.get(name.lower())
            (pq_groups if match else unknown).append(match or name)
        if unknown:
            print(f"error: unknown --pq-groups value(s): {', '.join(unknown)}. "
                  f"Known groups: {', '.join(PQ_GROUPS)}.", file=sys.stderr)
            return 1
    reports, meta, horizons = build_reports(
        profiles, timeout=args.timeout, enumerate_versions=not args.no_enumerate,
        workers=args.workers, baseline_path=args.baseline,
        update_baseline=args.update_baseline, do_pq_probe=not args.no_pq,
        pq_groups=pq_groups, do_chain=not args.no_chain, progress=progress,
        horizon_scenario=args.horizon, crqc_year=args.crqc_year,
        rule_paths=[p.strip() for p in args.rules.split(",")] if args.rules else None,
        use_builtin_rules=not args.no_builtin_rules)

    # Write artifacts first so a console-rendering hiccup never loses them.
    _write_file = _write_text

    if args.json:
        _write_file(args.json, EXPORTERS["json"](reports, meta))
    if args.ndjson:
        _write_file(args.ndjson, EXPORTERS["ndjson"](reports, meta))

    if args.format:
        formats = [f.strip() for f in args.format.split(",") if f.strip()]
        unknown = [f for f in formats if f not in EXPORTERS]
        if unknown:
            print(f"error: unknown format(s): {', '.join(unknown)}. "
                  f"Choose from {', '.join(EXPORTERS)}.", file=sys.stderr)
            return 1
        for fmt in formats:
            path = _write_export(fmt, reports, meta, args.out_dir)
            print(f"wrote {path}", file=sys.stderr)

    min_sev = _SEVERITY_BY_NAME.get(args.min_severity, Severity.INFO)
    print(render_console(reports, meta, color=_want_color(args.no_color),
                         min_severity=min_sev, quiet=args.quiet, horizon_assets=horizons))

    # CI gate
    if args.fail_on != "none":
        threshold = _SEVERITY_BY_NAME[args.fail_on]
        worst = max((f.severity for r in reports for f in r.findings), default=Severity.INFO)
        if worst >= threshold:
            print(f"\nfail-on={args.fail_on}: highest finding severity is {worst.label}", file=sys.stderr)
            return 2
    return 0


def _cmd_code(args) -> int:
    if not os.path.exists(args.path):
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 1

    report = scan_path(args.path)
    meta = {
        "tool_version": __version__,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "scan_type": "code",
        "root": report.root,
        "files_scanned": report.files_scanned,
    }

    _write_file = _write_text

    if args.json:
        _write_file(args.json, json_out.code_to_json(report, meta))
    if args.ndjson:
        _write_file(args.ndjson, json_out.code_to_ndjson(report, meta))
    if args.cyclonedx:
        _write_file(args.cyclonedx, cyclonedx.code_to_cyclonedx(report, meta))

    min_sev = _SEVERITY_BY_NAME.get(args.min_severity, Severity.INFO)
    print(render_code_console(report, meta, color=_want_color(args.no_color), min_severity=min_sev))

    if args.fail_on != "none":
        threshold = _SEVERITY_BY_NAME[args.fail_on]
        worst = max((f.severity for f in report.findings), default=Severity.INFO)
        if worst >= threshold:
            print(f"\nfail-on={args.fail_on}: highest finding severity is {worst.label}", file=sys.stderr)
            return 2
    return 0


def _cmd_passive(args) -> int:
    if not os.path.exists(args.log):
        print(f"error: log not found: {args.log}", file=sys.stderr)
        return 1

    report = measure(args.log, min_connections=args.min_connections)
    meta = {
        "tool_version": __version__,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "scan_type": "passive",
        "source": report.source,
    }

    _write_file = _write_text

    if args.json:
        _write_file(args.json, json_out.passive_to_json(report, meta))
    if args.ndjson:
        _write_file(args.ndjson, json_out.passive_to_ndjson(report, meta))

    min_sev = _SEVERITY_BY_NAME.get(args.min_severity, Severity.INFO)
    print(render_passive_console(report, meta, color=_want_color(args.no_color), min_severity=min_sev))

    if args.fail_on != "none":
        threshold = _SEVERITY_BY_NAME[args.fail_on]
        worst = max((f.severity for f in report.findings), default=Severity.INFO)
        if worst >= threshold:
            print(f"\nfail-on={args.fail_on}: highest finding severity is {worst.label}", file=sys.stderr)
            return 2
    return 0


def _cmd_export(args) -> int:
    if not os.path.exists(args.input):
        print(f"error: report not found: {args.input}", file=sys.stderr)
        return 1
    try:
        with open(args.input, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        reports = reports_from_document(doc)
    except (OSError, ValueError, TypeError, AttributeError, json.JSONDecodeError) as exc:
        print(f"error: could not load QER report from {args.input}: {exc}", file=sys.stderr)
        return 1
    if not reports:
        print("error: report contains no endpoints.", file=sys.stderr)
        return 1

    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    unknown = [f for f in formats if f not in EXPORTERS]
    if unknown:
        print(f"error: unknown format(s): {', '.join(unknown)}. "
              f"Choose from {', '.join(EXPORTERS)}.", file=sys.stderr)
        return 1

    meta = {
        "tool_version": (doc.get("tool_version") or __version__),
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": args.input,
        "reexported": True,
    }

    if not args.out_dir and len(formats) == 1:
        content = EXPORTERS[formats[0]](reports, meta)
        if args.output:
            _write_text(args.output, content)
        else:
            print(content)                       # pipeable to stdout
        return 0

    if not args.out_dir:
        print("error: multiple formats require --out-dir.", file=sys.stderr)
        return 1
    for fmt in formats:
        path = _write_export(fmt, reports, meta, args.out_dir)
        print(f"wrote {path}", file=sys.stderr)
    return 0


def _cmd_ike(args) -> int:
    result = scan_ike(args.host, port=args.port, timeout=args.timeout)
    meta = {"tool_version": __version__,
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat()}
    if args.json:
        doc = {"tool": "qer", "tool_version": __version__, "scan_type": "ike",
               "meta": meta, "result": to_serializable(result)}
        _write_text(args.json, json.dumps(doc, indent=2))

    print(render_ike_console(result, meta, color=_want_color(args.no_color)))
    if args.raw and result.raw_response_hex:
        print(f"\nraw IKE response ({len(result.raw_response_hex) // 2} bytes):", file=sys.stderr)
        print(result.raw_response_hex, file=sys.stderr)

    if args.fail_on != "none":
        threshold = _SEVERITY_BY_NAME[args.fail_on]
        worst = max((f.severity for f in result.findings), default=Severity.INFO)
        if worst >= threshold:
            print(f"\nfail-on={args.fail_on}: highest finding severity is {worst.label}", file=sys.stderr)
            return 2
    return 0


def _cmd_ssh(args) -> int:
    result = scan_ssh(args.host, port=args.port, timeout=args.timeout)
    meta = {"tool_version": __version__,
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat()}
    if args.json:
        doc = {"tool": "qer", "tool_version": __version__, "scan_type": "ssh",
               "meta": meta, "result": to_serializable(result)}
        _write_text(args.json, json.dumps(doc, indent=2))

    print(render_ssh_console(result, meta, color=_want_color(args.no_color)))

    if args.fail_on != "none":
        threshold = _SEVERITY_BY_NAME[args.fail_on]
        worst = max((f.severity for f in result.findings), default=Severity.INFO)
        if worst >= threshold:
            print(f"\nfail-on={args.fail_on}: highest finding severity is {worst.label}", file=sys.stderr)
            return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="qer",
        description="GreyNOC Quantum Exposure Radar — cryptographic bill-of-materials scanner "
                    "and post-quantum readiness monitor.")
    p.add_argument("--version", action="version", version=f"qer {__version__}")
    sub = p.add_subparsers(dest="command", metavar="{scan,code,passive,export,ike,ssh}")

    s = sub.add_parser("scan", help="scan endpoints and build the CBOM / migration map")
    s.add_argument("hosts", nargs="*",
                   help="targets as host[:port], CIDR (10.0.0.0/24), or range (10.0.0.5-40)")
    s.add_argument("-f", "--file", help="targets file (.json profiles or annotated text)")
    s.add_argument("-t", "--timeout", type=float, default=6.0, help="per-connection timeout seconds (default 6)")
    s.add_argument("--no-enumerate", action="store_true",
                   help="skip per-version probing (faster; only the preferred version is recorded)")
    s.add_argument("--no-pq", action="store_true",
                   help="skip the active post-quantum / hybrid key-exchange probe")
    s.add_argument("--no-chain", action="store_true",
                   help="skip full certificate-chain capture (leaf certificate only)")
    s.add_argument("--starttls",
                   help="force a STARTTLS dialect for all targets "
                        "(smtp|imap|pop3|ldap|postgres|mysql|none); default: infer from port")
    s.add_argument("--pq-groups",
                   help="comma list of PQ groups to probe, case-insensitive; unknown names error out "
                        "(default: X25519MLKEM768,SecP256r1MLKEM768,X25519Kyber768Draft00)")
    s.add_argument("--horizon", default="baseline",
                   choices=["aggressive", "baseline", "conservative"],
                   help="CRQC-arrival scenario for the exposure horizon (default baseline ~2035)")
    s.add_argument("--crqc-year", type=int,
                   help="override the CRQC arrival year for the horizon (e.g. 2032)")
    s.add_argument("--rules",
                   help="extra detection rule pack(s): comma list of .json/.yaml files or directories")
    s.add_argument("--no-builtin-rules", action="store_true",
                   help="disable the built-in rule pack (qer-builtin)")
    s.add_argument("--workers", type=int, default=16, help="concurrent scan workers (default 16)")
    s.add_argument("--discover", action="store_true",
                   help="connect-scan the targets across --ports first, then deep-scan only open services")
    s.add_argument("--ports", help="discovery port list, e.g. 443,8443,587,993 (default: common TLS/STARTTLS)")
    s.add_argument("--discover-timeout", type=float, default=2.0,
                   help="per-port connect timeout for --discover (default 2s)")
    s.add_argument("--baseline", help="baseline JSON file for the downgrade monitor")
    s.add_argument("--update-baseline", action="store_true",
                   help="write/refresh the baseline after scanning")
    s.add_argument("--json", help="write the full JSON report to this path")
    s.add_argument("--ndjson", help="write the NDJSON findings feed to this path")
    s.add_argument("--out-dir", default="out", help="directory for --format exports (default ./out)")
    s.add_argument("--format", help="comma list of exports to write into --out-dir: "
                                    + ",".join(EXPORTERS))
    s.add_argument("--min-severity", default="info", choices=list(_SEVERITY_BY_NAME),
                   help="hide console findings below this severity")
    s.add_argument("--fail-on", default="none",
                   choices=["none"] + list(_SEVERITY_BY_NAME),
                   help="exit code 2 if any finding reaches this severity (CI gate)")
    s.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    s.add_argument("--quiet", action="store_true", help="suppress per-endpoint detail and progress")
    s.set_defaults(func=_cmd_scan)

    c = sub.add_parser("code", help="scan a codebase for crypto usage, secrets, and dependencies")
    c.add_argument("path", help="file or directory to scan")
    c.add_argument("--json", help="write the full JSON report to this path")
    c.add_argument("--ndjson", help="write the NDJSON findings feed to this path")
    c.add_argument("--cyclonedx", help="write a CycloneDX 1.6 CBOM to this path")
    c.add_argument("--min-severity", default="info", choices=list(_SEVERITY_BY_NAME),
                   help="hide findings below this severity")
    c.add_argument("--fail-on", default="none", choices=["none"] + list(_SEVERITY_BY_NAME),
                   help="exit code 2 if any finding reaches this severity (CI gate)")
    c.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    c.set_defaults(func=_cmd_code)

    pa = sub.add_parser("passive", help="measure PQ coverage of real traffic from a Zeek ssl.log")
    pa.add_argument("log", help="path to a Zeek ssl.log (TSV or JSON)")
    pa.add_argument("--min-connections", type=int, default=1,
                    help="ignore services with fewer than N observed connections")
    pa.add_argument("--json", help="write the full JSON report to this path")
    pa.add_argument("--ndjson", help="write the NDJSON findings feed to this path")
    pa.add_argument("--min-severity", default="info", choices=list(_SEVERITY_BY_NAME),
                    help="hide findings below this severity")
    pa.add_argument("--fail-on", default="none", choices=["none"] + list(_SEVERITY_BY_NAME),
                    help="exit code 2 if any finding reaches this severity (CI gate)")
    pa.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    pa.set_defaults(func=_cmd_passive)

    e = sub.add_parser("export", help="re-emit a saved JSON report in any format (no re-scan)")
    e.add_argument("-i", "--input", required=True, help="a QER JSON report (from `qer scan --json`)")
    e.add_argument("-f", "--format", default="cyclonedx",
                   help="comma list of formats: " + ",".join(EXPORTERS))
    e.add_argument("-o", "--output", help="write a single format to this path (else stdout)")
    e.add_argument("--out-dir", help="write each format to this directory")
    e.set_defaults(func=_cmd_export)

    ik = sub.add_parser("ike", help="scan a VPN gateway's IKEv2 crypto over UDP/500 (unit-verified, best-effort)")
    ik.add_argument("host", help="VPN gateway host or IP")
    ik.add_argument("--port", type=int, default=500, help="IKE UDP port (default 500)")
    ik.add_argument("--timeout", type=float, default=5.0, help="UDP response timeout seconds (default 5)")
    ik.add_argument("--json", help="write the JSON result to this path")
    ik.add_argument("--raw", action="store_true", help="print the gateway's raw IKE response hex")
    ik.add_argument("--fail-on", default="none", choices=["none"] + list(_SEVERITY_BY_NAME),
                    help="exit code 2 if any finding reaches this severity (CI gate)")
    ik.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    ik.set_defaults(func=_cmd_ike)

    sh = sub.add_parser("ssh", help="inventory an SSH server's key-exchange/host-key/cipher crypto (PQ-aware)")
    sh.add_argument("host", help="SSH host or IP")
    sh.add_argument("--port", type=int, default=22, help="SSH TCP port (default 22)")
    sh.add_argument("--timeout", type=float, default=6.0, help="connection timeout seconds (default 6)")
    sh.add_argument("--json", help="write the JSON result to this path")
    sh.add_argument("--fail-on", default="none", choices=["none"] + list(_SEVERITY_BY_NAME),
                    help="exit code 2 if any finding reaches this severity (CI gate)")
    sh.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    sh.set_defaults(func=_cmd_ssh)
    return p


def _force_utf8() -> None:
    """Windows consoles default to cp1252 and cannot encode the report's box /
    bar glyphs. Reconfigure stdio to UTF-8 (replacing anything unmappable)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main(argv=None) -> int:
    _force_utf8()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):     # no subcommand -> show help (friendly for the .exe)
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except KeyboardInterrupt:  # pragma: no cover
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
