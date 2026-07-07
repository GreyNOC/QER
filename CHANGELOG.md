# Changelog

All notable changes to GreyNOC Quantum Exposure Radar (QER) are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.2] — 2026-07-07

A self-QA/QC pass over the v0.2.1 changeset itself: a 4-dimension adversarial
review (regressions / interaction effects / coverage / docs) of the just-shipped
fixes confirmed 12 issues (0 false positives). All fixed. 268 tests (was 257),
coverage 79% → 81%.

### Fixed
- **Codescan regression from the v0.2.1 hex guard** — the `x448`/`x25519`
  lookbehind over-excluded camelCase identifiers, so `generateX25519()` /
  `newX448()` were no longer flagged (a false negative v0.2.0 didn't have). The
  guard now excludes only the `0x` hex-literal prefix.
- **Self-contradicting IKE finding on PQ gateways** — the new ML-KEM entries
  (IDs 35–37) made a post-quantum gateway emit `QER-IKE-DH` "Quantum-vulnerable
  IKE key exchange" with `quantum_risk: pq-safe` in the same finding. The finding
  is now gated on actual risk, and PQ groups get a positive `QER-IKE-PQ-OK`.
- **"Probe disabled" vs "probe errored" disambiguated** — an all-errored PQ probe
  (v0.2.1's untestable state) was reported by `QER-PQ-UNVERIFIED` as "probe
  disabled (--no-pq)". A new `ScanResult.pq_probe_ran` field distinguishes the
  states and the finding now says which happened and what to do.
- **`legacy_only` is now visible** — v0.2.1 set and serialized the flag but never
  displayed it; the console endpoint block and HTML report card now show
  `legacy-only (SECLEVEL=0)`.

### Added
- Regression/coverage tests for the v0.2.1 branches that shipped untested:
  legacy-retry failure path, leaf-unparseable certificate-key fallback,
  `--discover` annotation preservation, STARTTLS read caps, Zeek `unknown-`
  codepoint fallback, IKE ML-KEM finding gating.

### Docs
- `--pq-groups` help text now states the real default (3 groups) and the new
  validation behavior; README test count and example banner brought current.

## [0.2.1] — 2026-07-06

A whole-project QA/QC pass. Three parallel review agents (protocol scanners,
classification/scoring logic, exporters/CLI) raised 34 findings; adversarial
verification (one skeptic per finding, plus IANA-registry fact-checks)
**confirmed 16 real issues and refuted 2**. All 16 are fixed with regression
tests. 257 tests (was 220).

### Fixed
- **Legacy-only endpoints no longer vanish** — the primary handshake ran only at
  the default OpenSSL security level, so a TLS 1.0-only / legacy-cipher-only
  appliance was reported *unreachable* instead of flagged. It now retries once at
  `SECLEVEL=0` and tags the result `legacy_only`.
- **False CRITICAL PQ-downgrade alert eliminated** — when every PQ probe errored
  (all groups unreachable, or a typo'd `--pq-groups`), `probe_pq` reported a
  confident "no PQ support", which could fire a bogus `QER-DG-PQ` page against a
  baseline that had seen PQ. All-errored probes are now *untestable*
  (`pq_kex_negotiated=None`), and `--pq-groups` values are validated/canonicalised
  (unknown names error out).
- **IKEv2 encryption codepoints corrected to IANA** — transform ID 23 was labelled
  `AES-CCM-16`; per the registry 23 is `Camellia-CBC` and `AES-CCM-16` is ID 16.
  The DH/key-exchange table gained the RFC 5114 MODP groups, brainpool, GOST, and
  the standardised **ML-KEM** key-exchange methods (IDs 35–37, classified PQ-safe).
- **Passive PQ measurement no longer inverted on older Zeek** — a hybrid group
  logged by raw codepoint (`unknown-4588` = X25519MLKEM768, etc.) was counted as
  *classical*, so a fully-PQ service read as "0% PQ, all HNDL-exposed". Known
  codepoints are now resolved; the emitted Zeek script recognises both spellings.
- **Emitted Zeek script: no `No_Forward_Secrecy` storm on TLS 1.3** — TLS 1.3 suite
  names carry no `ECDHE` token but are always forward-secret; they are now matched
  explicitly.
- **Rule engine: multi-key conditions are implicit-AND** — a `{scan, certificate}`
  condition silently evaluated only one leg; both legs must now hold, and an empty
  condition never fires.
- **Classification fixes** — anonymous suites (`ADH-*`/`AECDH-*`) are ephemeral and
  now scored forward-secret (not static-RSA); SHAKE128/256 signatures (RFC 8692) are
  no longer mislabelled SHA-1; MD2/MD4 signature hashes are now `broken-now`;
  XMSS/HSS-LMS (NIST SP 800-208) classify as PQ-safe.
- **`QER-DG-PROTO` risk reflects the landed version** — a TLS 1.3→1.2 downgrade is
  `quantum-vulnerable`, not hardcoded `broken-now` (only a drop to TLS ≤1.1 is).
- **Code-scanner false positives removed** — bare "des" in prose no longer trips the
  weak-cipher rule; `x448`/`x25519` no longer match hex literals (`0x448`); the
  Falcon *web framework* no longer reads as PQ (level-qualified now). New detections:
  Java `SHA1withRSA`/`HmacSHA1`, single-quoted `alg:'none'`, and `python-jose`/
  `node-jose` dependencies.
- **Deserializer fails safe** — an unknown `quantum_risk` label (e.g. from a newer
  QER) now deserializes to `quantum-vulnerable`, not the best-case `pq-safe`.
- **STARTTLS reads are bounded** — an LDAP BER length (up to 4 GiB) or an endless
  SMTP multiline reply could exhaust memory within the deadline; reads are now capped.
- **Certificate chain: leaf position by original index** — an unparseable leaf no
  longer promotes an intermediate CA to `leaf`.
- **SSH: no confident verdict on incomplete scans** — a banner-read-then-KEXINIT-fail
  now prints "scan incomplete" instead of a false "no post-quantum key exchange".

### Changed
- Default PQ probe set adds `SecP256r1MLKEM768` (CNSA/enterprise stacks enable only
  the P-256 hybrid).

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
