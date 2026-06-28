# GreyNOC Quantum Exposure Radar (QER)

> Don't build a new cipher. Build the thing defenders actually lack: **visibility.**

QER is a **defensive** scanner and monitor that builds a live cryptographic bill
of materials (CBOM), classifies every primitive against the quantum threat,
scores post‑quantum (PQC) migration readiness, flags **harvest‑now‑decrypt‑later
(HNDL)** exposure, watches for **hybrid/PQ downgrades**, and emits ready‑to‑load
**SIEM** detection content and an **executive migration map**.

This repository is the **v0.1 MVP**: the *Network/TLS radar* vertical slice. It
performs real TLS handshakes, parses real certificates, and produces real
findings. See [Scope & honesty](#scope--honesty) for exactly what is and isn't
implemented yet, and [Roadmap](#roadmap) for the rest of the vision.

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

---

## Quick start

```bash
# Scan a couple of hosts
qer scan github.com cloudflare.com:443

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
```

Example console output:

```
GreyNOC Quantum Exposure Radar  v0.1.0
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

## Code & dependency scan (`qer code`)

The offline companion to the network radar. It walks a repo and inventories
cryptography *in source*, feeding the same `Finding` model, quantum
classification, and NDJSON SIEM feed:

* asymmetric usage (RSA / DSA / DH / ECDSA / Ed25519 / X25519) — quantum‑vulnerable
* broken‑now primitives (MD5, SHA‑1, DES/3DES, RC4)
* JWT/JWS signing algorithms — `RS*/ES*/PS*/EdDSA`, and the dangerous `alg:none` (critical)
* post‑quantum libraries (ML‑KEM/Kyber, ML‑DSA/Dilithium, SLH‑DSA, liboqs) — a *good* signal
* hardcoded PEM private keys (a secret‑in‑repo finding) and certificates
* SSH keys (by type) and crypto libraries in dependency manifests

```bash
qer code . --min-severity medium
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
  scanner.py     active TLS handshakes + certificate parsing
  pqprobe.py     raw TLS 1.3 probe: hybrid/PQ support + enforcement (preference) probe
  cert_chain.py  raw TLS 1.2 probe: full certificate-chain (PKI CBOM) capture
  passive.py     measured PQ coverage from a Zeek ssl.log (`qer passive`)
  scoring.py     HNDL / risk / readiness scores + finding generation
  downgrade.py   baseline snapshot + regression diffing
  codescan.py    offline code & dependency crypto scanner (`qer code`)
  report.py      console reports + executive migration map
  targets.py     load AssetProfiles from file / CLI
  cli.py         argparse entrypoint (`qer scan`, `qer code`, `qer passive`, `qer export`)
  siem/          json/ndjson + cyclonedx (CBOM) + html dashboard + sigma/splunk/kql/zeek
tests/           93 offline unit tests for the pure logic
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
* **The code scanner is heuristic** (regex over text). Like grep‑based SAST it
  matches crypto terms in comments and string literals; it is an inventory aid,
  not proof of exploitable usage.
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
- [ ] **VPN (IKE/IPsec) crypto inventory.**
- [ ] **SAML signing‑method** detection in the code scanner.
- [x] **CycloneDX 1.6 CBOM output** — standards-compliant cryptographic bill of materials ([cyclonedx.py](qer/siem/cyclonedx.py)).
- [x] **`qer export`** — re‑emit any format from a saved JSON report, no re-scan.
- [x] **Web "radar" dashboard** — self-contained offline HTML ([html_report.py](qer/siem/html_report.py)).
- [ ] **STIX/TAXII** output.

---

## License

MIT — see [LICENSE](LICENSE).
