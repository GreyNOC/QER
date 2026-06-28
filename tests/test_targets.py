from qer.models import Exposure
from qer.targets import (parse_target_line, profile_from_dict,
                        profiles_from_args, split_host_port)


def test_split_host_port_default():
    assert split_host_port("github.com") == ("github.com", 443)


def test_split_host_port_explicit():
    assert split_host_port("example.com:8443") == ("example.com", 8443)


def test_split_host_port_strips_scheme_and_path():
    assert split_host_port("https://example.com:9000/login") == ("example.com", 9000)


def test_split_host_port_ipv6_bracket():
    assert split_host_port("[2001:db8::1]:9443") == ("2001:db8::1", 9443)


def test_parse_target_line_with_annotations():
    p = parse_target_line('payments.internal:8443 label="Card processor" '
                          'sensitivity=5 shelf_life=15 exposure=external agility=2 expect_pq=true')
    assert (p.host, p.port) == ("payments.internal", 8443)
    assert p.label == "Card processor"
    assert p.sensitivity == 5
    assert p.shelf_life_years == 15
    assert p.exposure == Exposure.EXTERNAL
    assert p.crypto_agility == 2
    assert p.expect_pq is True


def test_parse_target_line_comment_and_blank():
    assert parse_target_line("# a comment") is None
    assert parse_target_line("   ") is None


def test_profile_from_dict_coerces_exposure():
    p = profile_from_dict({"host": "x", "exposure": "internal", "sensitivity": 4})
    assert p.exposure == Exposure.INTERNAL
    assert p.sensitivity == 4


def test_profiles_from_args():
    ps = profiles_from_args(["a.com", "b.com:8443"])
    assert [(p.host, p.port) for p in ps] == [("a.com", 443), ("b.com", 8443)]
