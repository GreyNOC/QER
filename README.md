# GreyNOC Quantum Exposure Radar (QER)

[![CI](https://github.com/GreyNOC/QER/actions/workflows/ci.yml/badge.svg)](https://github.com/GreyNOC/QER/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

> Don't build a new cipher. Build the thing defenders actually lack: **visibility.**

QER is a **defensive** scanner and monitor that builds a live cryptographic bill
of materials (CBOM), classifies every primitive against the quantum threat,
scores post‑quantum (PQC) migration readiness, flags **harvest‑now‑decrypt‑later
(HNDL)** exposure, watches for **hybrid/PQ downgrades**, and emits ready‑to‑load
**SIEM** detection content and an **executive migration map**.

It performs real handshakes, parses real certificates, and produces real
findings — now across **TLS, STARTTLS-wrapped services (mail/LDAP/databases),
and SSH**, with quantum exposure quantified in *years* and an extensible rule
engine. See [Scope & honesty](#scope--honesty) for exactly what is and isn't
implemented, and [Roadmap](#roadmap) for the rest of the vision.

---

## Why

A cryptographically relevant quantum computer (CRQC) breaks the hard problems
behind RSA, finite‑field Diffie‑Hellman, and elliptic‑curve crypto (ECDH/ECDSA/
EdDSA) via Shor's algorithm. The dangerous part isn't the future — it's **today**:
an adversary can record TLS traffic now and decrypt it later once a CRQC exists.
By **Mosca's inequality**, you have a problem whenever

```
(data secrecy lifetime) + (migration time) > (time until a CRQC exists)
```

Defenders can't migrate what they can't see. QER is the inventory + risk + alert
layer that tells you *which systems to fix first and why.*

---

## Install

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows  (source .venv/bin/activate on *nix)
pip install -e .                    # or: pip install -r requirements.txt
```

Requires Python ≥ 3.10 and the [`cryptography`](https://pypi.org/project/cryptography/)
package (for certificate parsing). Everything else is the standard library.

**Portable binary (no Python required):** download a single self-contained
executable for **Linux / macOS / Windows** from the
[latest release](https://github.com/GreyNOC/QER/releases/latest)
(`qer-linux-x64`, `qer-macos-arm64`, `qer-windows-x64.exe`). On Linux/macOS,
`chmod +x` it first. Build one yourself with `packaging/build-exe.ps1` (Windows)
or `pyinstaller --onefile --name qer --collect-submodules qer packaging/qer_entry.py`.

```bash
./qer-linux-x64 scan github.com
qer-windows-x64.exe code . --cyclonedx cbom.json
```

### Make `qer` a global command

With the editable install (`pip install -e .`), `qer` is already on your PATH
**while the venv is active**. To call `qer` from anywhere *without* activating
the venv — e.g. when using the portable binary — drop it on your PATH:

**Windows (PowerShell)** — copy the binary into a personal `bin` and add it to your user PATH (idempotent):

```powershell
$bin = "$env:USERPROFILE\bin"; New-Item -ItemType Directory -Force $bin | Out-Null
Copy-Item .\dist\qer.exe "$bin\qer.exe" -Force   # or your downloaded qer-windows-x64.exe
$p = [Environment]::GetEnvironmentVariable("Path","User")
if (($p -split ';') -notcontains $bin) { [Environment]::SetEnvironmentVariable("Path", "$p;$bin", "User") }
# open a NEW terminal, then:  qer --version
```

**Linux / macOS** — drop the binary on your PATH:

```bash
install -m 0755 qer-linux-x64 ~/.local/bin/qer    # ensure ~/.local/bin is on PATH
qer --version
```

> A PATH change only takes effect in **newly opened** terminals — existing
> windows read PATH at launch.

---

## Quick start

```bash
# Scan a couple of hosts
qer scan github.com cloudflare.com:443

# Sweep a whole network: discover live TLS/STARTTLS services, then deep-scan them
qer scan 10.0.0.0/24 --discover --ports 443,8443,587,993

# Mail / database TLS via STARTTLS (auto-detected from the port)
qer scan smtp.example.com:587 imap.example.com:143 db.example.com:5432

# Inventory an SSH server's PQ posture (detects sntrup761 / mlkem768 hybrid KEX)
qer ssh github.com

# Quantify exposure in YEARS (Mosca horizon) under an early-CRQC scenario
qer scan -f data/targets.example.txt --horizon aggressive

# Add your own detection policy with a rule pack (JSON; YAML if PyYAML present)
qer scan example.com --rules rules/example-rules.json

# Scan a target list with business context, diff against a baseline,
# and emit every SIEM format into ./out
qer scan -f data/targets.example.txt \
         --baseline .qer_baseline.json --update-baseline \
         --out-dir out --format json,ndjson,sigma,splunk,kql,zeek

# CI gate: non‑zero exit if anything reaches HIGH
qer scan -f data/targets.json --fail-on high

# Offline code & dependency scan (shift‑left)
qer code path/to/repo --json out/code.json --fail-on high

# Measure PQ coverage of real traffic from a Zeek ssl.log
qer passive /var/log/zeek/ssl.log --min-connections 5

# Scan once, re-emit to any format later (no re-scan)
qer scan example.com --json report.json
qer export -i report.json -f cyclonedx,sigma,splunk,kql --out-dir siem/

# Self-contained HTML "radar" dashboard (open offline in any browser)
qer scan -f data/targets.example.txt --format html --out-dir out   # -> out/qer-radar.html

# VPN gateway IKEv2 crypto inventory (UDP/500) — unit-verified, best-effort
qer ike vpn.example.com --json out/ike.json
```

Example console output:

```
GreyNOC Quantum Exposure Radar  v0.2.1
Scanned 3 endpoint(s), 3 reachable  |  OpenSSL 3.0.13

CRYPTOGRAPHIC BILL OF MATERIALS
────────────────────────────────────────────────────────────────
● cloudflare.com:443  [NOW]  risk  79  hndl  40  diff  10
    TLSv1.3  TLS_AES_256_GCM_SHA384  kex=ECDHE  fs=yes
    legacy accepted: TLSv1.1, TLSv1.0
    cert: ECDSA-256 secp256r1  sig=ecdsa-with-SHA256  expires 41d
      HIGH  QER-PROTO-LEGACY  Legacy TLS versions accepted: TLSv1.1, TLSv1.0
      MED   QER-HNDL  Harvest-now-decrypt-later exposure (HNDL risk 40/100)
      MED   QER-CERT-PQ  Quantum-vulnerable certificate (ECDSA-256)

EXECUTIVE MIGRATION MAP
────────────────────────────────────────────────────────────────
Wave 1 — migrate now (2)
  • cloudflare.com:443  Edge/CDN
      risk ████████··  79   hndl  40   diff  10 ★ quick win
Wave 2 — soon (1)
  • github.com:443  Source control
      risk █████·····  48   hndl  49   diff  25 ★ quick win
```

---

## How it classifies crypto

All classification lives in [`qer/classify.py`](qer/classify.py) — pure logic,
no I/O. Each primitive gets one of four quantum‑risk levels:

| Level | Meaning | Examples |
|------|---------|----------|
| `broken-now` | Weak today, independent of quantum | TLS ≤ 1.1, RC4, 3DES, MD5/SHA‑1 sigs, RSA < 2048 |
| `quantum-vulnerable` | Broken by Shor's algorithm | RSA, DH/DHE, ECDH/ECDHE, ECDSA, EdDSA |
| `quantum-weakened` | Halved by Grover but usable | AES‑128 (~64‑bit post‑Grover) |
| `pq-safe` | Post‑quantum / hybrid, or strong symmetric | ML‑KEM/Kyber, ML‑DSA, AES‑256, ChaCha20, X25519MLKEM768 |

The key insight the tool encodes: **`ECDHE‑RSA‑AES256‑GCM‑SHA384` is
`quantum-vulnerable`, not safe.** AES‑256 is fine, but the *ECDHE key exchange*
is the HNDL problem — a recorded handshake is decryptable once a CRQC exists.
Forward secrecy protects you against a *classical* future key theft, not a
quantum one.

## Scoring (`qer/scoring.py`)

* **HNDL risk (0–100)** — the marquee metric. Driven specifically by
  quantum‑vulnerable **key exchange** (not signatures — you can't retroactively
  forge a signature over already‑accepted traffic), weighted by data shelf life,
  sensitivity, and exposure. RSA key transport (no forward secrecy) is the worst
  case; PQ/hybrid key exchange scores 0.
* **risk_score (0–100)** — overall migration urgency: HNDL combined with
  present‑day hygiene (legacy TLS, lost forward secrecy, weak ciphers, expiry).
* **migration_difficulty (0–100)** — mostly the inverse of crypto agility.
* **readiness (0–100)** — how modern/agile the endpoint already is (a quick‑win
  signal, *not* a claim it's post‑quantum).
* **priority** — `NOW` / `SOON` / `LATER` / `OK`, the basis of the migration map.

Business context (sensitivity, shelf life, exposure, agility) is supplied by you
per target — the scanner measures the crypto, you supply the stakes, QER combines
them. See [the targets file](#targets-file).

## Downgrade monitor (`qer/downgrade.py`)

Snapshot an endpoint's posture, then on every re‑scan alert when it **regresses**:
TLS version drops, forward secrecy is lost, the cipher or key shrinks, newly‑
accepted legacy versions appear, or a previously‑negotiated **PQ/hybrid key
exchange disappears** (the headline hybrid‑downgrade alert — `QER-DG-PQ`,
emitted at *critical*). Enforcement can also *relax* without fully disappearing
(`QER-DG-PQ-ENFORCE`). Use `--baseline FILE [--update-baseline]`.

## Post‑quantum: support, enforcement, and measured coverage

QER answers PQ at three increasing levels of confidence:

1. **Support** — does the server offer a hybrid group at all? [`qer/pqprobe.py`](qer/pqprobe.py)
   sends a raw TLS 1.3 ClientHello advertising *only* the hybrid group with an
   empty key share; a HelloRetryRequest selecting it proves support on any
   OpenSSL.
2. **Enforcement** — does it *insist* on PQ, or merely tolerate it? The
   **preference probe** offers `[hybrid, x25519]` *with* an x25519 key share. If
   the server still HelloRetryRequests for the hybrid group it **enforces** PQ;
   if it completes classically it only **tolerates** it (the common case — even
   Cloudflare/Google accept classical when the client offers it). Enforcement
   drives HNDL lower (kex factor 0.05 vs 0.15 for mere support).
3. **Measured coverage** — what fraction of *real* traffic actually got PQ?
   `qer passive` reads a Zeek `ssl.log` (TSV or JSON) and reports the share of
   observed connections whose negotiated `curve` is hybrid, per service —
   turning "supported" into a measured **% protected** and surfacing the
   classical‑client tail that is still HNDL‑exposed. [`qer/passive.py`](qer/passive.py)

```bash
qer scan cloudflare.com            # support + enforcement, live
qer passive /var/log/zeek/ssl.log  # measured % PQ coverage of real traffic
```

The emitted Zeek script ([`qer export ... zeek`](qer/siem/zeek.py)) adds a
`qer_pq` column to `ssl.log`, so the sensor that flags weak TLS in real time also
produces the data `qer passive` consumes.

## SSH crypto inventory (`qer ssh`)

SSH is one of the largest, least-inventoried HNDL surfaces in any estate — admin
sessions, git, and tunneled databases, almost all key-exchanged with classical
(EC)DH. `qer ssh` speaks just enough of the SSH-2.0 transport ([RFC 4253](https://www.rfc-editor.org/rfc/rfc4253))
to read the server's `KEXINIT` — the preference-ordered name-lists of every
key-exchange, host-key, cipher and MAC it offers — without authenticating or
completing a handshake. Because the lists are in preference order, QER reports
not just whether a **hybrid PQ key exchange** is *offered* but whether it is
*preferred* (the SSH analogue of TLS enforce-vs-tolerate). Modern OpenSSH (≥ 9.0)
prefers `sntrup761x25519-sha512@openssh.com`; 9.9+ adds `mlkem768x25519-sha256`.

```bash
qer ssh github.com          # → "post-quantum key exchange PREFERRED (sntrup761x25519-sha512)"
qer ssh ssh.example.com --json out/ssh.json
```

## Beyond HTTPS: STARTTLS (`qer scan`)

A huge share of an organisation's TLS — and quantum exposure — is not on port
443. `qer scan` transparently upgrades plaintext services to TLS via their
native STARTTLS handshake, then runs the *full* QER engine over it (handshake,
version enumeration, certificate chain, **and the active PQ probe**). The dialect
is inferred from the port (override with `--starttls`):

| Service | Ports | Service | Ports |
|---------|-------|---------|-------|
| SMTP | 25, 587, 2525 | LDAP | 389, 3268 |
| IMAP | 143 | PostgreSQL | 5432 |
| POP3 | 110 | MySQL | 3306 |

```bash
qer scan smtp.example.com:587      # auto-STARTTLS, then "is my mail server PQ-ready?"
qer scan db:5432 --starttls postgres
```

## Quantum exposure horizon (Mosca, in years)

A 0–100 HNDL score says *which* endpoints to fix first; the horizon says *how
exposed you already are*, in years. It makes [Mosca's inequality](https://eprint.iacr.org/2015/1075)
concrete — `shelf-life + migration-time > years-to-CRQC` — against a named,
citable CRQC-arrival scenario (`aggressive` ~2030 / `baseline` ~2035 /
`conservative` ~2040, or `--crqc-year`). Each exposed endpoint gets a **shortfall
in years** and a **start-by date**; the fleet gets an `EXPOSURE HORIZON` panel
and a `QER-HORIZON` finding that flows into every SIEM/CBOM export.

```
QUANTUM EXPOSURE HORIZON
scenario: aggressive (CRQC ~2030)   2/2 HNDL endpoints already exposed
  ▲ github.com:443  +16y overhang   shelf 15y + migrate 5y vs 4y to CRQC   start-by 2010
```

## Extensible detection rules (`--rules`)

Beyond the built-in findings, QER runs a small, eval-free **rule engine** over a
normalized view of each scan. Defenders encode their own policy in declarative
**rule packs** (JSON always; YAML if PyYAML is installed) — no Python — and every
rule-derived finding carries a **confidence** (0–1) and **provenance**
(`pack/rule` id). The match DSL is boolean `all`/`any`/`not` over leaf conditions
that test `scan` facts or assert some `primitive`/`certificate` matches; operators
are field-name suffixes (`algorithm_contains`, `bits_lt`, `supported_versions_has`…).
See [`rules/example-rules.json`](rules/example-rules.json).

```bash
qer scan example.com --rules rules/example-rules.json          # add a pack
qer scan example.com --no-builtin-rules --rules my-policy/     # only your packs
```

## Network sweep & discovery

Targets can be single hosts, **CIDR blocks** (`10.0.0.0/24`), or **ranges**
(`10.0.0.5-40`). With `--discover`, QER first runs a fast concurrent TCP
connect-scan across a port set and then deep-scans only the *open* TLS/STARTTLS
services — turning a subnet into a fleet-level PQ-posture inventory in one run.

```bash
qer scan 10.0.0.0/24 --discover --ports 443,8443,587,993,5432
# → Fleet  37 reachable   29 PQ-capable (78%)   12 PQ-enforced   8 HNDL-exposed
```

## Code & dependency scan (`qer code`)

The offline companion to the network radar. It walks a repo and inventories
cryptography *in source*, feeding the same `Finding` model, quantum
classification, and NDJSON SIEM feed:

* asymmetric usage (RSA / DSA / DH / ECDSA / Ed25519 / X25519) — quantum‑vulnerable
* broken‑now primitives (MD5, SHA‑1, DES/3DES, RC4)
* JWT/JWS signing algorithms — `RS*/ES*/PS*/EdDSA`, and the dangerous `alg:none` (critical)
* SAML / XML‑DSig signature & digest methods — SHA‑1/MD5 (broken), RSA/ECDSA XML signatures (quantum‑vulnerable), plus SAML libraries
* post‑quantum libraries (ML‑KEM/Kyber, ML‑DSA/Dilithium, SLH‑DSA, liboqs) — a *good* signal
* hardcoded PEM private keys (a secret‑in‑repo finding) and certificates
* SSH keys (by type) and crypto libraries in dependency manifests

```bash
qer code . --min-severity medium
qer code . --cyclonedx cbom.json   # emit a CycloneDX 1.6 CBOM of code crypto (file:line evidence)
```

Every finding carries a `file:line` location. The scan is **heuristic**
(pattern matching over text, like grep‑based SAST): it will match crypto terms
in comments and string literals, so treat it as an inventory/triage aid, not a
proof of exploitable usage. [codescan.py](qer/codescan.py)

## SIEM output (`qer/siem/`)

| Format | What it is |
|--------|-----------|
| `json` | Full nested report (CBOM + findings + scores) |
| `ndjson` | One denormalised event per finding — the canonical SIEM feed |
| `cyclonedx` | **CycloneDX 1.6 CBOM** — a standards-compliant cryptographic bill of materials (crypto-asset components for protocols, certificates, and algorithms) |
| `stix` | **STIX 2.1 bundle** — actionable exposures as `vulnerability` SDOs linked to asset identities, ready to share over TAXII |
| `html` | **Self-contained "radar" dashboard** — a single offline HTML file (no external deps) with the migration map, per-endpoint CBOM, PQ status, and findings |
| `sigma` | Portable Sigma rules over the QER feed **and** over Zeek `ssl` telemetry |
| `splunk` | SPL searches + `savedsearches.conf` alert stanzas (`sourcetype=qer:finding`) |
| `kql` | Microsoft Sentinel / Log Analytics queries over a `QER_CL` custom table |
| `zeek` | A Zeek policy script that flags weak/quantum‑vulnerable TLS **on the wire** |

The `ndjson` event schema (see [`qer/siem/json_out.py`](qer/siem/json_out.py)) is
the contract the Sigma/Splunk/KQL content is written against.

---

## Targets file

`.json` (full profiles) or annotated text — see
[`data/targets.example.txt`](data/targets.example.txt):

```
host[:port]  label="Name" sensitivity=1..5 shelf_life=<years>
             exposure=internal|partner|external agility=1..5 expect_pq=true|false
```

Unannotated lines use sensible defaults (`sensitivity=3, shelf_life=5,
exposure=external, agility=3`).

---

## Architecture

```
qer/
  models.py      dataclasses + JSON serialization (the shared data model)
  classify.py    crypto knowledge base — names → quantum-risk (pure logic)
  scanner.py     active TLS handshakes + certificate parsing + CIDR discovery sweep
  pqprobe.py     raw TLS 1.3 probe: hybrid/PQ support + enforcement (preference) probe
  cert_chain.py  raw TLS 1.2 probe: full certificate-chain (PKI CBOM) capture
  starttls.py    opportunistic-TLS negotiation (smtp/imap/pop3/ldap/postgres/mysql)
  sshscan.py     raw SSH-2.0 KEXINIT inventory + PQ-KEX detection (`qer ssh`)
  ikescan.py     raw IKEv2 IKE_SA_INIT probe: VPN/IPsec crypto inventory (`qer ike`)
  passive.py     measured PQ coverage from a Zeek ssl.log (`qer passive`)
  scoring.py     HNDL / risk / readiness scores + finding generation
  horizon.py     Mosca exposure horizon — HNDL expressed in years (CRQC scenarios)
  rules.py       declarative rule engine + confidence (extensible detection packs)
  downgrade.py   baseline snapshot + regression diffing
  codescan.py    offline code & dependency crypto scanner (`qer code`)
  report.py      console reports + executive migration map + exposure-horizon panel
  targets.py     load AssetProfiles from file / CLI; CIDR + range expansion
  cli.py         argparse entrypoint (`qer scan` / `ssh` / `code` / `passive` / `export` / `ike`)
  siem/          json/ndjson + cyclonedx (CBOM) + stix + html dashboard + sigma/splunk/kql/zeek
tests/           257 offline unit tests for the pure logic
```

Run the tests:

```bash
pip install -e ".[test]"
pytest -q
```

---

## Scope & honesty

QER is deliberately honest about its limits rather than overclaiming:

* **Active PQ probing works** via [`qer/pqprobe.py`](qer/pqprobe.py) — a
  dependency‑free raw TLS 1.3 ClientHello that proves hybrid‑group support on any
  OpenSSL (verified live against Cloudflare/Google). The **preference probe**
  further distinguishes *enforcement* from mere *tolerance*, and `qer passive`
  measures the actual PQ share of real traffic — so the old "support ≠
  negotiation" gap is now addressed at three levels (support → enforcement →
  measured coverage). The one residual: a support/enforcement probe still
  reflects server behaviour, not a census of every client.
* **Full certificate-chain CBOM works** via [`qer/cert_chain.py`](qer/cert_chain.py) —
  a raw TLS 1.2 handshake captures the plaintext `Certificate` message and parses
  every link (leaf + intermediate CAs), since stdlib `ssl` exposes only the leaf on
  3.11. TLS 1.3-only servers encrypt that message, so QER falls back to the stdlib
  leaf there (use `--no-chain` to skip chain capture entirely).
* **SSH and STARTTLS scanning are live‑verified.** `qer ssh` reads the server's
  real `KEXINIT` (verified against OpenSSH/GitLab — `sntrup761x25519` and
  `mlkem768x25519` detected correctly); STARTTLS PQ probing is verified against
  live SMTP/IMAP (e.g. Gmail submission *enforces* `X25519MLKEM768`). The SSH
  scan reads the server's *offer*, not what a specific client negotiates.
* **The exposure horizon is a planning model, not a prediction.** It computes
  Mosca's inequality against an explicit, citable CRQC‑arrival *scenario*; the
  scenario (and any `--crqc-year`) is shown on every output so no single guess is
  smuggled in as fact.
* **The code scanner is heuristic** (regex over text). Like grep‑based SAST it
  matches crypto terms in comments and string literals; it is an inventory aid,
  not proof of exploitable usage.
* **The IKEv2 scanner (`qer ike`) is unit‑verified, not live‑proven.** Its packet
  builder and parser are round‑trip tested against constructed packets, but —
  unlike every TLS feature — it has not been validated against a live VPN gateway
  (no public IKE responder was available and UDP/500 egress is often filtered).
  Treat live IKE results as best‑effort.
* QER is an **inventory and risk‑visibility** tool. It does not exploit,
  intercept, or modify traffic. Scan only systems you are authorized to assess.

---

## Roadmap

Shipped so far: the *Network/TLS radar*, active PQ probing, and the code &
dependency scanner. Still ahead:

- [x] **Active PQ/hybrid probing** — dependency‑free raw TLS 1.3 probe ([pqprobe.py](qer/pqprobe.py)).
- [x] **Preference probe** — distinguishes PQ *enforcement* from mere tolerance.
- [x] **Passive PQ measurement** — measured % coverage from a Zeek ssl.log ([passive.py](qer/passive.py)).
- [x] **Code & dependency scan** — RSA/ECDSA/DH usage, crypto‑library imports,
      JWT signing algorithms, hardcoded keys, dependency manifests ([codescan.py](qer/codescan.py)).
- [x] **Full certificate‑chain / PKI CBOM** — raw TLS 1.2 chain capture ([cert_chain.py](qer/cert_chain.py)).
- [x] **SAML signing‑method** detection in the code scanner ([codescan.py](qer/codescan.py)).
- [x] **VPN (IKE/IPsec) crypto inventory** — raw IKEv2 `IKE_SA_INIT` probe ([ikescan.py](qer/ikescan.py)). *Unit‑verified only* — see [Scope & honesty](#scope--honesty).
- [x] **CycloneDX 1.6 CBOM output** — standards-compliant cryptographic bill of materials ([cyclonedx.py](qer/siem/cyclonedx.py)).
- [x] **`qer export`** — re‑emit any format from a saved JSON report, no re-scan.
- [x] **Web "radar" dashboard** — self-contained offline HTML ([html_report.py](qer/siem/html_report.py)).
- [x] **STIX 2.1 / TAXII** output — exposures as a shareable STIX bundle ([stix.py](qer/siem/stix.py)).
- [x] **SSH crypto inventory** — raw SSH-2.0 KEXINIT, PQ-KEX-aware (`qer ssh`, [sshscan.py](qer/sshscan.py)).
- [x] **STARTTLS** — PQ/TLS scanning over SMTP/IMAP/POP3/LDAP/PostgreSQL/MySQL ([starttls.py](qer/starttls.py)).
- [x] **Quantum exposure horizon** — HNDL expressed in *years* via Mosca's inequality ([horizon.py](qer/horizon.py)).
- [x] **Extensible rule engine** — declarative detection packs + confidence scoring ([rules.py](qer/rules.py)).
- [x] **CIDR sweep + discovery** — inventory a whole network's PQ posture in one run.

---

## License

MIT — see [LICENSE](LICENSE).
