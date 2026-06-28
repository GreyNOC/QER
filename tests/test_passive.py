import os

from qer.passive import (aggregate, classify_curve, measure, parse_ssl_log,
                        record_pq_kind)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
TSV = os.path.join(FIXTURES, "ssl_tsv.log")
JSON = os.path.join(FIXTURES, "ssl_json.log")


def test_classify_curve():
    assert classify_curve("X25519MLKEM768") == "pq"
    assert classify_curve("x25519") == "classical"
    assert classify_curve("secp256r1") == "classical"
    assert classify_curve("-") == "none"
    assert classify_curve("") == "none"


def test_parse_tsv_reads_all_rows_and_curve():
    recs = parse_ssl_log(TSV)
    assert len(recs) == 5
    curves = [r["curve"] for r in recs]
    assert "X25519MLKEM768" in curves and "x25519" in curves


def test_tsv_aggregation_pq_percentage():
    report = measure(TSV)
    assert report.total_connections == 5
    api = next(s for s in report.services if s.service == "api.example.com")
    assert api.pq == 2 and api.classical == 2
    assert api.pq_pct == 50


def test_partial_finding_emitted():
    report = measure(TSV)
    ids = {f.id for f in report.findings}
    assert "QER-PASSIVE-PARTIAL" in ids


def test_legacy_service_counts_no_group_connections():
    report = measure(TSV)
    legacy = next(s for s in report.services if s.service == "legacy.example.com")
    assert legacy.none == 1 and legacy.pq == 0


def test_json_format_parses_equivalently():
    report = measure(JSON)
    api = next(s for s in report.services if s.service == "api.example.com")
    assert api.pq == 1 and api.classical == 1 and api.pq_pct == 50


def test_min_connections_filter():
    report = measure(TSV, min_connections=5)
    # only api.example.com has >= 5? It has 4; legacy has 1 -> none qualify
    assert all(s.total >= 5 for s in report.services)


def test_record_pq_kind_prefers_qer_pq_column():
    # Explicit qer_pq column wins, even when the curve field was dropped.
    assert record_pq_kind({"qer_pq": "T", "curve": ""}) == "pq"
    assert record_pq_kind({"qer_pq": "F", "curve": ""}) == "classical"
    assert record_pq_kind({"qer_pq": "true", "curve": ""}) == "pq"
    # falls back to curve classification when the column is absent
    assert record_pq_kind({"qer_pq": "", "curve": "X25519MLKEM768"}) == "pq"
    assert record_pq_kind({"qer_pq": "", "curve": "x25519"}) == "classical"


def test_json_nested_id_does_not_collapse_to_unknown(tmp_path):
    p = tmp_path / "ssl.log"
    p.write_text(
        '{"id":{"resp_h":"104.16.0.1","resp_p":443},"curve":"X25519MLKEM768"}\n'
        '{"id":{"resp_h":"8.8.8.8","resp_p":853},"curve":"x25519"}\n', encoding="utf-8")
    services = {s.service for s in measure(str(p)).services}
    assert "104.16.0.1:443" in services and "unknown" not in services


def test_custom_empty_field_token_is_normalized(tmp_path):
    p = tmp_path / "ssl.log"
    p.write_text(
        "#separator \\x09\n"
        "#unset_field\t-\n"
        "#empty_field\tEMPTY\n"
        "#fields\tid.resp_h\tid.resp_p\tcurve\tserver_name\n"
        "10.0.0.1\t443\tEMPTY\tEMPTY\n", encoding="utf-8")
    rec = parse_ssl_log(str(p))[0]
    assert rec["curve"] == "" and rec["server_name"] == ""


def test_qer_pq_column_drives_measurement(tmp_path):
    # curve dropped, only the boolean column present -> still measured correctly
    p = tmp_path / "ssl.log"
    p.write_text(
        '{"id.resp_h":"10.0.0.1","id.resp_p":443,"server_name":"svc","qer_pq":true}\n'
        '{"id.resp_h":"10.0.0.1","id.resp_p":443,"server_name":"svc","qer_pq":false}\n',
        encoding="utf-8")
    svc = next(s for s in measure(str(p)).services if s.service == "svc")
    assert svc.pq == 1 and svc.classical == 1 and svc.pq_pct == 50
