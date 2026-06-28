# Changelog

All notable changes to GreyNOC Quantum Exposure Radar (QER) are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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

[0.1.0]: https://github.com/GreyNOC/QER/releases/tag/v0.1.0
