"""Regression tests for report rendering robustness (review fixes)."""

from __future__ import annotations

from qer.models import AssetProfile, EndpointReport, ScanResult
from qer.report import render_console


def test_render_console_reachable_but_unscored_does_not_crash():
    # A reachable endpoint with scores=None (e.g. a partially-loaded report) must
    # render facts without an AttributeError on s.risk_score.
    scan = ScanResult(host="h", port=443, reachable=True,
                      negotiated_version="TLSv1.3", negotiated_cipher="TLS_AES_256_GCM_SHA384",
                      key_exchange="ECDHE", forward_secret=True)
    rep = EndpointReport(profile=AssetProfile(host="h"), scan=scan, findings=[], scores=None)
    out = render_console([rep], {"tool_version": "0.2.0"}, color=False)
    assert "h:443" in out
