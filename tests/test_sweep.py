"""Tests for CIDR/range expansion, discovery, and the ports parser."""

from __future__ import annotations

import pytest

from qer import scanner
from qer.cli import _parse_ports
from qer.scanner import discover_services
from qer.targets import (MAX_SWEEP_HOSTS, expand_host_token, profiles_from_args,
                         split_host_port)


# --------------------------------------------------------------------------- #
# Expansion
# --------------------------------------------------------------------------- #

def test_expand_cidr_excludes_net_and_broadcast():
    hosts = expand_host_token("192.168.1.0/29")
    assert hosts == [f"192.168.1.{i}" for i in range(1, 7)]   # .1 .. .6


def test_expand_cidr_31_and_32_keep_all():
    assert expand_host_token("10.0.0.0/31") == ["10.0.0.0", "10.0.0.1"]
    assert expand_host_token("10.0.0.5/32") == ["10.0.0.5"]


def test_expand_range():
    assert expand_host_token("10.0.0.10-12") == ["10.0.0.10", "10.0.0.11", "10.0.0.12"]


def test_expand_passthrough_for_plain_host():
    assert expand_host_token("example.com") == ["example.com"]
    assert expand_host_token("bad/notacidr") == ["bad/notacidr"]


def test_expand_cap_is_enforced_and_announced(capsys):
    hosts = expand_host_token("10.0.0.0/18")            # 16382 usable -> capped
    assert len(hosts) == MAX_SWEEP_HOSTS
    assert "capped" in capsys.readouterr().err


def test_split_host_port_is_cidr_aware():
    assert split_host_port("10.0.0.0/24") == ("10.0.0.0/24", 443)
    assert split_host_port("10.0.0.0/24:8443") == ("10.0.0.0/24", 8443)
    assert split_host_port("10.0.0.5-40") == ("10.0.0.5-40", 443)
    # regression: ordinary host:port and dashed hostnames must be unaffected
    assert split_host_port("example.com:443") == ("example.com", 443)
    assert split_host_port("my-host.example.com") == ("my-host.example.com", 443)


def test_profiles_from_args_expands_cidr_with_port():
    ps = profiles_from_args(["10.0.0.0/30:993"])
    assert [p.host for p in ps] == ["10.0.0.1", "10.0.0.2"]
    assert all(p.port == 993 for p in ps)


def test_split_host_port_rejects_fake_cidr_hostname():
    # regression: an all-hex hostname with a path must NOT be kept as a "CIDR";
    # the path is stripped like any other URL path.
    assert split_host_port("fee.fed/admin") == ("fee.fed", 443)
    assert split_host_port("dead.beef/12") == ("dead.beef", 443)   # not a real network
    assert split_host_port("10.0.0.0/24") == ("10.0.0.0/24", 443)  # real CIDR still kept


def test_expand_huge_cidr_is_bounded_not_materialized(capsys):
    # regression: a /8 must not eagerly build 16M strings before the cap
    hosts = expand_host_token("10.0.0.0/8")
    assert len(hosts) == MAX_SWEEP_HOSTS
    assert "capped" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# Ports parser
# --------------------------------------------------------------------------- #

def test_parse_ports_list_range_dedup():
    assert _parse_ports("443, 8443 ,8000-8002,443") == [443, 8443, 8000, 8001, 8002]


def test_parse_ports_drops_out_of_range():
    assert _parse_ports("0,70000,443") == [443]


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #

class _FakeConn:
    def close(self):
        pass


def test_discover_services_finds_open_ports(monkeypatch):
    open_set = {("a", 443), ("b", 22)}

    def fake_conn(addr, timeout=None):
        if (addr[0], addr[1]) in open_set:
            return _FakeConn()
        raise OSError("refused")

    monkeypatch.setattr(scanner.socket, "create_connection", fake_conn)
    found = discover_services(["a", "b"], [443, 22], timeout=1, workers=4)
    assert found == [("a", 443), ("b", 22)]


def test_discover_services_empty_when_all_closed(monkeypatch):
    monkeypatch.setattr(scanner.socket, "create_connection",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("refused")))
    assert discover_services(["x"], [443, 8443], timeout=1) == []
