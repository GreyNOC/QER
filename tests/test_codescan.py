import os

from qer.codescan import scan_path

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "sample_app")


def _ids(report):
    return {f.id for f in report.findings}


def test_scans_fixture_files():
    report = scan_path(FIXTURE)
    assert report.files_scanned >= 4


def test_detects_asymmetric_and_weak_and_jwt():
    ids = _ids(scan_path(FIXTURE))
    assert "QER-CODE-RSA" in ids
    assert "QER-CODE-EC" in ids
    assert "QER-CODE-MD5" in ids
    assert "QER-CODE-JWT-ASYM" in ids
    assert "QER-CODE-JWT-NONE" in ids
    assert "QER-CODE-WEAKCIPHER" in ids        # des-ede3 in auth.js


def test_detects_secrets_and_ssh_and_deps_and_pq():
    ids = _ids(scan_path(FIXTURE))
    assert "QER-CODE-PRIVKEY" in ids
    assert "QER-CODE-SSHKEY" in ids
    assert "QER-CODE-DEP" in ids
    assert "QER-CODE-PQ" in ids


def test_jwt_none_is_critical():
    report = scan_path(FIXTURE)
    none_findings = [f for f in report.findings if f.id == "QER-CODE-JWT-NONE"]
    assert none_findings and none_findings[0].severity.label == "critical"


def test_every_finding_has_a_location():
    report = scan_path(FIXTURE)
    assert all(f.location for f in report.findings)
