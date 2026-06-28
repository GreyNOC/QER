# Validating `qer ike` against a live gateway

`qer ike` is **unit-verified** — its IKEv2 `IKE_SA_INIT` builder and parser are
round-trip tested (including an end-to-end loopback UDP test), but it has not yet
been confirmed against a real VPN gateway in this project. This guide is how to
promote it to *live-proven* against a gateway **you are authorized to scan**.

> Only scan systems you own or have explicit permission to assess.

## Quick check (capture the raw response)

```bash
qer ike <gateway-host> --raw --json out/ike.json
```

`--raw` prints the gateway's raw IKE response bytes (hex) to stderr; `--json`
records the parsed result plus `raw_response_hex`. The hex is the ground truth —
keep it so the parse can be re-checked offline.

## Stand up a known responder with strongSwan (Docker)

The cleanest authorized target is a local responder. Using the official
strongSwan image:

```bash
docker run --rm -d --name ss --cap-add NET_ADMIN -p 500:500/udp \
  strongx509/strongswan:latest \
  /bin/sh -c "swanctl --load-all 2>/dev/null; /usr/libexec/ipsec/charon"
# (or any IKEv2 responder config that listens on UDP/500)

qer ike 127.0.0.1 --raw
docker rm -f ss
```

Native alternative: install `strongswan` or `libreswan`, configure an IKEv2
`conn`, start the daemon, and `qer ike 127.0.0.1`.

## What a correct result looks like

A reachable IKEv2 responder yields, for example:

```
  IKEv2.0   responder=True
  Negotiated transforms
    encryption   AES-GCM-16-256             pq-safe
    prf          HMAC-SHA2-256              pq-safe
    integrity    HMAC-SHA2-256-128          pq-safe
    dh-group     MODP-2048                  quantum-vulnerable
  Findings
    MED   QER-IKE-DH   Quantum-vulnerable IKE key exchange (MODP-2048)
```

Confirm against the gateway's actual configured proposal (`swanctl --list-conns`
or the vendor console) that the `dh-group` / encryption / integrity QER reports
match what the gateway selected.

## Cross-check with a reference tool

Compare QER's output against an established scanner on the same target:

```bash
ike-scan <gateway-host>          # NTA ike-scan, if available
nmap -sU -p 500 --script ike-version <gateway-host>
```

The negotiated transforms should agree. If they don't, capture the `--raw` hex
and open an issue with it attached.

## Reporting

If you validate (or find a discrepancy) against a real gateway, please attach the
`--raw` hex and the gateway's configured proposal so the IKE caveat in the README
can be updated. Until then, treat live IKE results as best-effort.
