"""Tests for the CRQC exposure-horizon quantifier (qer.horizon)."""

from __future__ import annotations

from qer.horizon import (DEFAULT_SCENARIO, SCENARIOS, assess, fleet_horizon,
                         get_scenario, horizon_finding, migration_years,
                         mosca_shortfall)
from qer.models import AssetProfile, Severity


def _profile(shelf, agility, host="h", port=443):
    return AssetProfile(host=host, port=port, shelf_life_years=shelf, crypto_agility=agility)


def test_mosca_shortfall_math():
    assert mosca_shortfall(15, 5, 10) == 10
    assert mosca_shortfall(2, 1, 10) == -7


def test_migration_years_mapping():
    assert migration_years(5) == 1.0
    assert migration_years(1) == 7.0
    assert migration_years(99) == 3.0          # unknown -> default


def test_get_scenario():
    assert get_scenario(None).name == DEFAULT_SCENARIO
    assert get_scenario("aggressive").crqc_year == 2030
    assert get_scenario("nonsense").name == DEFAULT_SCENARIO


def test_assess_exposed():
    h = assess(_profile(15, 2), hndl_relevant=True, current_year=2025, scenario="baseline")
    assert h.verdict == "exposed"
    assert h.years_to_crqc == 10 and h.migration_years == 5
    assert h.shortfall_years == 10 and h.exposure_years == 10
    assert h.start_by_year == 2015 and h.complete_by_year == 2020


def test_assess_clear():
    h = assess(_profile(2, 5), hndl_relevant=True, current_year=2025, scenario="baseline")
    assert h.verdict == "clear"
    assert h.exposure_years == 0


def test_assess_not_relevant_is_na():
    h = assess(_profile(15, 1), hndl_relevant=False, current_year=2025)
    assert h.verdict == "n/a"


def test_assess_crqc_override():
    h = assess(_profile(10, 3), hndl_relevant=True, current_year=2025, crqc_year=2030)
    assert h.crqc_year == 2030 and h.years_to_crqc == 5
    assert "custom" in h.scenario


def test_horizon_finding_only_for_exposed():
    exposed = assess(_profile(15, 1), hndl_relevant=True, current_year=2025, scenario="aggressive")
    clear = assess(_profile(1, 5), hndl_relevant=True, current_year=2025, scenario="conservative")
    f = horizon_finding(exposed)
    assert f is not None and f.id == "QER-HORIZON" and f.category == "horizon"
    assert f.severity == Severity.HIGH                     # large overhang
    assert horizon_finding(clear) is None


def test_fleet_median_even_length_averages():
    # regression: even-length median must average the two middle values, not take upper
    items = [
        assess(_profile(13, 2, host="a"), True, 2025, "baseline"),   # shortfall 8
        assess(_profile(9, 2, host="b"), True, 2025, "baseline"),    # shortfall 4
    ]
    f = fleet_horizon(items)
    assert f.exposed == 2
    assert f.median_exposure_years == 6.0                            # (4 + 8) / 2, not 8


def test_fleet_horizon_aggregates():
    items = [
        assess(_profile(15, 2, host="a"), True, 2025, "baseline"),     # exposed +10
        assess(_profile(2, 5, host="b"), True, 2025, "baseline"),      # clear
        assess(_profile(20, 1, host="c"), False, 2025, "baseline"),    # n/a (not relevant)
    ]
    f = fleet_horizon(items)
    assert f.assessed == 3 and f.hndl_relevant == 2 and f.exposed == 1
    assert f.worst_shortfall_years == 10
    assert f.earliest_start_by_year == 2015
