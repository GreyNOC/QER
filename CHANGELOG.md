# Changelog

All notable changes to GreyNOC Quantum Exposure Radar (QER) are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.0] — 2026-06-28

A major expansion of the detection engine: QER now sees crypto well beyond
HTTPS, quantifies exposure in years, and is extensible by defenders. A
multi-agent adversarial review of the new code found and fixed 13 real bugs
(out of 22 raised; 9 false positives killed by verification). 220 tests.

### Added
- **SSH crypto inventory (`qer ssh`)** — a raw SSH-2.0 transport scanner
  ([RFC 4253](https://www.rfc-editor.org/rfc/rfc4253)) that reads the server's
  `KEXINIT` and classifies every offered key-exchange / host-key / cipher / MAC by
  quantum risk. Detects hybrid **post-quantum key exchange** (`sntrup761x25519`,
  `mlkem768x25519`) and whether it is *preferred* vs merely offered. Live-verified
  against OpenSSH (GitHub) and GitLab.
- **STARTTLS scanning** — `qer scan` transparently upgrades plaintext services to
  TLS via their native handshake and runs the full engine (handshake, version
  enumeration, certificate chain, **and the active PQ probe**) over them. Dialects:
  **SMTP, IMAP, POP3, LDAP, PostgreSQL, MySQL**, inferred from the port or forced
  with `--starttls`. Live-verified PQ-over-STARTTLS (Gmail submission enforces
  `X25519MLKEM768`).
- **Quantum exposure horizon** — HNDL expressed in *years* via Mosca's inequality
  against citable CRQC-arrival scenarios (`--horizon aggressive|baseline|conservative`,
  or `--crqc-year`). Per-endpoint *shortfall* and *start-by date*, a fleet
  `EXPOSURE HORIZON` panel, and a `QER-HORIZON` finding in every export.
- **Extensible rule engine (`--rules`)** — declarative detection packs (JSON; YAML
  with PyYAML) matched by a small, eval-free DSL, producing findings with a
  **confidence** (0–1) and **provenance**. A built-in pack ships; defenders add
  their own. `confidence` and `rule` are now on every finding and in the feeds.
- **Network sweep & discovery** — targets can be **CIDR** (`10.0.0.0/24`) or
  **ranges** (`10.0.0.5-40`); `--discover` connect-scans a port set and deep-scans
  only open TLS/STARTTLS services, with a fleet PQ-posture summary line.

### Fixed
- Target files are read as UTF-8 with BOM tolerance (`utf-8-sig`), so a
  Windows-authored list no longer parses its first host as `﻿host`.
- **Adversarial-review fixes (13):** SSH `gss-group14/16/18` no longer
  misclassified as broken (the `group1` substring trap); SSH read budget starts
  after connect. STARTTLS: SMTP `STARTTLS` detection is an exact EHLO-keyword
  match (no hostname false positives); MySQL checks the server's `CLIENT_SSL`
  capability and reports "SSL disabled" cleanly. PQ probe and certificate-chain
  reads are now bounded by one absolute deadline even with STARTTLS. CIDR
  expansion is `islice`-bounded so a `/8` can't materialize 16M strings; a
  hostname like `fee.fed/path` is no longer mistaken for a network. Rule engine:
  `_in` guards a non-list operand, `nonempty` treats numeric `0` as present, and
  unknown `match` keys are reported instead of silently ignored. Horizon median
  averages the two middle values for even-length fleets. The console no longer
  crashes on a reachable-but-unscored endpoint.

## [0.1.3] — 2026-06-28

A whole-project QA/QC pass (multi-agent audit + dynamic verification) found and
fixed 17 issues. Test coverage rose from 59% to 76%; 142 tests.

### Fixed
- **PQ enforcement detection was silently broken** — the HelloRetryRequest magic
  random (RFC 8446 §4.1.3) had a corrupted byte, so `qer scan` always reported a
  PQ-enforcing server as merely *tolerating* PQ (the `QER-PQ-OK (enforced)` and
  `QER-DG-PQ-ENFORCE` paths could never fire). Corrected the constant.
- **CycloneDX**: duplicate `bom-ref`s when the same `host:port` appeared in more
  than one report (and when a malformed cert had empty algorithm names) — now
  uniquely indexed, so the CBOM stays schema-valid.
- **Code scanner ReDoS**: an unterminated `-----BEGIN` flood in a scanned repo
  caused O(n²) backtracking (minutes). The PEM body is now length-bounded and
  gated on a closing marker.
- **`qer export` crash**: a valid-JSON but malformed report (`endpoints` not a
  list, or non-dict elements) raised an uncaught `AttributeError`; now a clean error.
- **Bare IPv6 targets** (e.g. `2001:db8::1`) were mis-split into host/port.
- **STIX**: an empty finding category no longer emits an empty `labels` string.
- **Consistency**: plain PSK key exchange (classified PQ-safe) no longer scores a
  non-zero HNDL risk.

### Internal
- Added test suites for the console renderers, JSON/Sigma/Splunk/KQL/Zeek
  exporters, the CLI handlers, and `scanner._parse_certificate`.

## [0.1.2] — 2026-06-28

### Added
- **Cross-platform release binaries.** A GitHub Actions release workflow
  (`.github/workflows/release.yml`) builds a single-file `qer` binary for
  **Linux (x64), macOS (arm64), and Windows (x64)** with PyInstaller on every
  `v*` tag, runs the test suite on each, and attaches the binaries plus the
  wheel and sdist to the GitHub Release automatically.

## [0.1.1] — 2026-06-28

### Added
- **Portable single-file `qer.exe`** for Windows (built with PyInstaller) — runs
  with no Python install. Attached to the release; build it yourself with
  `packaging/build-exe.ps1`.

### Changed
- Running `qer` with no subcommand now prints help and exits 0 (instead of an
  argparse error), which is friendlier when the `.exe` is launched directly.

### Fixed
- Committed the Zeek `ssl.log` test fixtures that the `*.log` gitignore rule had
  excluded, so the test suite passes from a clean checkout / on CI. (`v0.1.0`'s
  tag predates this fix; `v0.1.1` is the first release that is green on CI.)

## [0.1.0] — 2026-06-28

First release. A defensive cryptographic bill-of-materials scanner and
post-quantum (PQC) readiness monitor.

### Scanners (`qer scan`)
- Active TLS radar: handshake, protocol-version enumeration, cipher / key-exchange
  / forward-secrecy analysis, and leaf-certificate parsing.
- Full certificate-chain (PKI CBOM) capture via a raw TLS 1.2 probe.
- Active post-quantum probe (raw TLS 1.3): hybrid-group **support** and
  **enforcement** (preference) detection.
- HNDL ("harvest now, decrypt later") risk + PQC readiness scoring, with an
  executive migration map (NOW / SOON / LATER / OK).
- Baseline downgrade monitor: alerts on TLS-version / forward-secrecy / cipher /
  key-size / PQ-support / PQ-enforcement regressions.

### Other subcommands
- `qer code` — offline code & dependency scanner: RSA/EC/DH usage, JWT and
  SAML / XML-DSig signing algorithms, weak hashes/ciphers, hardcoded keys,
  SSH keys, post-quantum libraries, and crypto dependencies.
- `qer passive` — measured PQ coverage of real traffic from a Zeek `ssl.log`.
- `qer export` — re-emit any format from a saved JSON report without re-scanning.
- `qer ike` — IKEv2 VPN crypto inventory over UDP/500 *(unit-verified, best-effort)*.

### Export formats
- `json`, `ndjson` (canonical feeds)
- **CycloneDX 1.6** cryptographic bill of materials (`cyclonedx`)
- **STIX 2.1** bundle for TAXII threat-intel sharing (`stix`)
- Self-contained offline **HTML "radar" dashboard** (`html`)
- Sigma, Splunk SPL, Microsoft Sentinel KQL, and Zeek detection content

### Quality
- 112 offline unit tests.
- Every network feature live-verified against real endpoints.
- Built and hardened phase-by-phase; 15 real bugs caught and fixed by an
  adversarial multi-agent review pass.

[0.2.0]: https://github.com/GreyNOC/QER/releases/tag/v0.2.0
[0.1.3]: https://github.com/GreyNOC/QER/releases/tag/v0.1.3
[0.1.2]: https://github.com/GreyNOC/QER/releases/tag/v0.1.2
[0.1.1]: https://github.com/GreyNOC/QER/releases/tag/v0.1.1
[0.1.0]: https://github.com/GreyNOC/QER/releases/tag/v0.1.0
