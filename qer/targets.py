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

import json
import shlex
from typing import Iterable

from .models import AssetProfile, Exposure

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
    token = token.split("/", 1)[0]            # drop any path
    if token.startswith("["):                 # [ipv6]:port
        host, _, rest = token[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else default_port
        return host, port
    if ":" in token:
        head, _, tail = token.rpartition(":")
        if tail.isdigit():
            return head, int(tail)
    return token, default_port


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
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    if path.lower().endswith(".json"):
        data = json.loads(raw)
        if isinstance(data, dict):
            data = data.get("targets", [])
        return [profile_from_dict(d) for d in data]
    profiles = []
    for line in raw.splitlines():
        p = parse_target_line(line)
        if p:
            profiles.append(p)
    return profiles


def profiles_from_args(hosts: Iterable[str], default_port: int = 443) -> list[AssetProfile]:
    out = []
    for h in hosts:
        host, port = split_host_port(h, default_port)
        out.append(AssetProfile(host=host, port=port))
    return out
