"""Command-line interface for QER.

    qer scan github.com cloudflare.com:443
    qer scan -f targets.txt --baseline .qer_baseline.json --update-baseline \\
             --out-dir out --format json,ndjson,sigma,splunk,kql,zeek
    qer scan -f targets.json --fail-on high        # CI gate
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import ssl
import sys
from typing import Optional

from . import __version__
from .codescan import scan_path
from .downgrade import build_baseline, diff_reports, load_baseline, save_baseline
from .models import EndpointReport, Severity, reports_from_document
from .passive import measure
from .report import render_code_console, render_console, render_passive_console
from .scanner import scan_targets
from .scoring import generate_findings, score_endpoint
from .siem import EXPORTERS, json_out
from .targets import load_targets, profiles_from_args

_EXPORT_FILENAMES = {
    "json": "qer-report.json",
    "ndjson": "qer-findings.ndjson",
    "cyclonedx": "qer-cbom.cdx.json",
    "sigma": "qer-rules.sigma.yml",
    "splunk": "qer-splunk.spl",
    "kql": "qer-sentinel.kql",
    "zeek": "qer-quantum-radar.zeek",
}

_SEVERITY_BY_NAME = {s.label: s for s in Severity}


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


def build_reports(profiles, timeout: float, enumerate_versions: bool,
                  workers: int, baseline_path: Optional[str], update_baseline: bool,
                  do_pq_probe: bool = True, pq_groups=None, do_chain: bool = True,
                  progress=None) -> tuple[list[EndpointReport], dict]:
    scans = scan_targets(profiles, timeout=timeout,
                         enumerate_versions=enumerate_versions,
                         workers=workers, do_pq_probe=do_pq_probe,
                         pq_groups=pq_groups, do_chain=do_chain, progress=progress)
    by_key = {(s.host, s.port): s for s in scans}

    reports: list[EndpointReport] = []
    for p in profiles:
        scan = by_key.get((p.host, p.port))
        if scan is None:
            continue
        scores = score_endpoint(p, scan)
        findings = generate_findings(p, scan, scores)
        reports.append(EndpointReport(profile=p, scan=scan, findings=findings, scores=scores))

    # Downgrade monitor: diff against an existing baseline before updating it.
    if baseline_path:
        baseline = load_baseline(baseline_path)
        if baseline:
            diff_reports(reports, baseline)
        if update_baseline or baseline is None:
            save_baseline(build_baseline(reports), baseline_path)

    meta = {
        "tool_version": __version__,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "openssl": ssl.OPENSSL_VERSION,
        "endpoints": len(reports),
        "reachable": sum(1 for r in reports if r.scan.reachable),
    }
    return reports, meta


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

    def progress(profile, result):
        if args.quiet:
            return
        status = result.negotiated_version or (result.error or "unreachable")
        print(f"  scanned {profile.host}:{profile.port:<5}  {status}", file=sys.stderr)

    pq_groups = [g.strip() for g in args.pq_groups.split(",")] if args.pq_groups else None
    reports, meta = build_reports(
        profiles, timeout=args.timeout, enumerate_versions=not args.no_enumerate,
        workers=args.workers, baseline_path=args.baseline,
        update_baseline=args.update_baseline, do_pq_probe=not args.no_pq,
        pq_groups=pq_groups, do_chain=not args.no_chain, progress=progress)

    # Write artifacts first so a console-rendering hiccup never loses them.
    def _write_file(path: str, content: str) -> None:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"wrote {path}", file=sys.stderr)

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
                         min_severity=min_sev, quiet=args.quiet))

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

    def _write_file(path: str, content: str) -> None:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"wrote {path}", file=sys.stderr)

    if args.json:
        _write_file(args.json, json_out.code_to_json(report, meta))
    if args.ndjson:
        _write_file(args.ndjson, json_out.code_to_ndjson(report, meta))

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

    def _write_file(path: str, content: str) -> None:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"wrote {path}", file=sys.stderr)

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
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
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
            os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(content)
            print(f"wrote {args.output}", file=sys.stderr)
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="qer",
        description="GreyNOC Quantum Exposure Radar — cryptographic bill-of-materials scanner "
                    "and post-quantum readiness monitor.")
    p.add_argument("--version", action="version", version=f"qer {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan endpoints and build the CBOM / migration map")
    s.add_argument("hosts", nargs="*", help="targets as host[:port] (default port 443)")
    s.add_argument("-f", "--file", help="targets file (.json profiles or annotated text)")
    s.add_argument("-t", "--timeout", type=float, default=6.0, help="per-connection timeout seconds (default 6)")
    s.add_argument("--no-enumerate", action="store_true",
                   help="skip per-version probing (faster; only the preferred version is recorded)")
    s.add_argument("--no-pq", action="store_true",
                   help="skip the active post-quantum / hybrid key-exchange probe")
    s.add_argument("--no-chain", action="store_true",
                   help="skip full certificate-chain capture (leaf certificate only)")
    s.add_argument("--pq-groups",
                   help="comma list of PQ groups to probe (default: X25519MLKEM768,X25519Kyber768Draft00)")
    s.add_argument("--workers", type=int, default=16, help="concurrent scan workers (default 16)")
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
    try:
        return args.func(args)
    except KeyboardInterrupt:  # pragma: no cover
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
