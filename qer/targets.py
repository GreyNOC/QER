"""Loading scan targets and their business context.

Two formats:

* **JSON** (``.json``) — a list of objects, or ``{"targets": [...]}``. Each object
  may carry the full asset profile (sensitivity, shelf life, exposure, etc.).
* **Text** — one target per line. ``#`` starts a comment. Each line is
  ``host[:port]`` optionally followed by ``key=value`` annotations, e.g.::

      payments.internal:8443  label="Card processor" sensitivity=5 shelf_life=15 exposure=external agility=2 expect_pq=true

Unannotated lines just use the defaults in :class:`qer.models.AssetProfile`.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import itertools
import json
import re
import shlex
import socket
import sys
from typing import Iterable

from .models import AssetProfile, Exposure

# Upper bound on how many hosts a single CIDR/range token may expand to, so a
# fat-fingered /8 can't silently launch a 16-million-host sweep. The cap is
# always announced on stderr (never silent).
MAX_SWEEP_HOSTS = 4096

_RANGE_RE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")

_TRUE = {"1", "true", "yes", "y", "on"}
_KEY_ALIASES = {
    "shelf_life": "shelf_life_years",
    "shelf": "shelf_life_years",
    "agility": "crypto_agility",
    "sens": "sensitivity",
    "pq": "expect_pq",
}


def split_host_port(token: str, default_port: int = 443) -> tuple[str, int]:
    token = token.strip()
    # strip URL scheme if present
    for scheme in ("https://", "http://", "tls://"):
        if token.lower().startswith(scheme):
            token = token[len(scheme):]
    # CIDR (10.0.0.0/24) or last-octet range (10.0.0.5-40), optionally :port —
    # handled before the path-strip below, which would eat the "/prefix". A "/foo"
    # token is only treated as CIDR if it actually parses as a network, so a real
    # hostname like "fee.fed/path" still falls through to normal path-stripping.
    if "/" in token or "-" in token:
        core, sep, tail = token.rpartition(":")
        has_port = bool(sep) and tail.isdigit()
        cand = core if has_port else token
        if "/" in cand:
            try:
                ipaddress.ip_network(cand, strict=False)
                return cand, (int(tail) if has_port else default_port)
            except ValueError:
                pass
        elif _RANGE_RE.match(cand):
            return cand, (int(tail) if has_port else default_port)
    token = token.split("/", 1)[0]            # drop any path
    if token.startswith("["):                 # [ipv6]:port
        host, _, rest = token[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else default_port
        return host, port
    if token.count(":") > 1:                 # bare IPv6 literal, e.g. 2001:db8::1
        try:
            socket.inet_pton(socket.AF_INET6, token)
            return token, default_port
        except OSError:
            pass
    if ":" in token:
        head, _, tail = token.rpartition(":")
        if tail.isdigit():
            return head, int(tail)
    return token, default_port


def _cap(ips: list[str], token: str) -> list[str]:
    if len(ips) > MAX_SWEEP_HOSTS:
        print(f"note: '{token}' expands to {len(ips)} hosts; capped to {MAX_SWEEP_HOSTS} "
              f"(narrow the range or raise MAX_SWEEP_HOSTS).", file=sys.stderr)
        return ips[:MAX_SWEEP_HOSTS]
    return ips


def expand_host_token(host: str) -> list[str]:
    """Expand a CIDR (``10.0.0.0/24``) or last-octet range (``10.0.0.5-40``) into
    individual host strings. Anything else passes through unchanged (a single
    hostname/IP). CIDR network/broadcast addresses are excluded for IPv4 blocks
    wider than /31."""
    if "/" in host:
        try:
            net = ipaddress.ip_network(host, strict=False)
        except ValueError:
            return [host]                      # not a real network -> treat literally
        wide = net.prefixlen < (31 if net.version == 4 else 127)
        hosts_iter = net.hosts() if wide else iter(net)
        # islice the iterator so a fat /8 never materializes 16M strings before
        # the cap can trim it — take MAX+1 to detect (and announce) the overflow.
        ips = [str(ip) for ip in itertools.islice(hosts_iter, MAX_SWEEP_HOSTS + 1)]
        return _cap(ips, host)
    m = _RANGE_RE.match(host)
    if m:
        base, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
        if lo <= hi and hi <= 255:
            return _cap([f"{base}{i}" for i in range(lo, hi + 1)], host)
    return [host]


def _coerce(profile_kwargs: dict) -> dict:
    out = {}
    for k, v in profile_kwargs.items():
        k = _KEY_ALIASES.get(k, k)
        if k in ("sensitivity", "shelf_life_years", "crypto_agility", "port"):
            out[k] = int(v)
        elif k == "expect_pq":
            out[k] = str(v).lower() in _TRUE if not isinstance(v, bool) else v
        elif k == "exposure":
            out[k] = Exposure.parse(v)
        else:
            out[k] = v
    return out


def profile_from_dict(d: dict) -> AssetProfile:
    host = d.get("host") or d.get("hostname")
    if not host:
        raise ValueError(f"target object missing 'host': {d}")
    kwargs = {k: v for k, v in d.items() if k not in ("host", "hostname")}
    if "exposure" in kwargs:
        kwargs["exposure"] = Exposure.parse(kwargs["exposure"])
    return AssetProfile(host=host, **_coerce(kwargs))


def parse_target_line(line: str) -> AssetProfile | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = shlex.split(line)
    host, port = split_host_port(parts[0])
    kwargs: dict = {"port": port}
    for tok in parts[1:]:
        if "=" in tok:
            k, _, v = tok.partition("=")
            kwargs[k.strip()] = v.strip()
    return AssetProfile(host=host, **_coerce(kwargs))


def load_targets(path: str) -> list[AssetProfile]:
    # utf-8-sig transparently strips a leading BOM (common in Windows-authored
    # target files) so the first host isn't parsed as "﻿host".
    with open(path, "r", encoding="utf-8-sig") as fh:
        raw = fh.read()
    if path.lower().endswith(".json"):
        data = json.loads(raw)
        if isinstance(data, dict):
            data = data.get("targets", [])
        return [profile_from_dict(d) for d in data]
    profiles = []
    for line in raw.splitlines():
        p = parse_target_line(line)
        if not p:
            continue
        # A CIDR/range line applies its annotations to every expanded host.
        expanded = expand_host_token(p.host)
        if len(expanded) == 1 and expanded[0] == p.host:
            profiles.append(p)
        else:
            profiles.extend(dataclasses.replace(p, host=ip) for ip in expanded)
    return profiles


def profiles_from_args(hosts: Iterable[str], default_port: int = 443) -> list[AssetProfile]:
    out = []
    for h in hosts:
        host, port = split_host_port(h, default_port)
        for ip in expand_host_token(host):
            out.append(AssetProfile(host=ip, port=port))
    return out
