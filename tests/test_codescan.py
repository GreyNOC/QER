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


def test_detects_saml_xmldsig_signing():
    ids = _ids(scan_path(FIXTURE))
    assert "QER-CODE-SAML" in ids          # SAML / XML-DSig usage inventory
    assert "QER-CODE-SAML-WEAK" in ids     # rsa-sha1 signature + sha1 digest
    assert "QER-CODE-SAML-SIG" in ids      # rsa-sha256 XML signature (quantum-vulnerable)


def test_saml_dependency_flagged_quantum_vulnerable():
    report = scan_path(FIXTURE)
    deps = [f for f in report.findings if f.id == "QER-CODE-DEP" and "python3-saml" in f.title]
    assert deps and deps[0].quantum_risk.label == "quantum-vulnerable"


def test_saml_sig_covers_rsa_pss_and_dsa(tmp_path):
    # RSA-PSS uses digest-first order (sha256-rsa-MGF1); xmldsig11 carries dsa-sha256.
    p = tmp_path / "idp.xml"
    p.write_text(
        '<ds:SignatureMethod Algorithm="http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"/>\n'
        '<ds:SignatureMethod Algorithm="http://www.w3.org/2009/xmldsig11#dsa-sha256"/>\n',
        encoding="utf-8")
    assert "QER-CODE-SAML-SIG" in {f.id for f in scan_path(str(p)).findings}


def test_saml_usage_no_false_positive_on_bare_signature(tmp_path):
    # A WPF/XAML or string-literal <Signature> with no XML-DSig namespace must NOT
    # be flagged as SAML usage.
    p = tmp_path / "App.cs"
    p.write_text('var x = "<Signature>"; // <Signature.Content> attached property\n', encoding="utf-8")
    assert "QER-CODE-SAML" not in {f.id for f in scan_path(str(p)).findings}


def test_jwt_none_is_critical():
    report = scan_path(FIXTURE)
    none_findings = [f for f in report.findings if f.id == "QER-CODE-JWT-NONE"]
    assert none_findings and none_findings[0].severity.label == "critical"


def test_every_finding_has_a_location():
    report = scan_path(FIXTURE)
    assert all(f.location for f in report.findings)


def test_unterminated_pem_flood_is_not_a_dos(tmp_path):
    # A file full of `-----BEGIN` with no matching END used to be O(n^2) (minutes).
    import time
    p = tmp_path / "flood.txt"
    p.write_text("-----BEGIN PRIVATE KEY-----\n" * 50000, encoding="utf-8")
    start = time.monotonic()
    report = scan_path(str(p))
    assert time.monotonic() - start < 5.0
    assert not any(f.id == "QER-CODE-PRIVKEY" for f in report.findings)
