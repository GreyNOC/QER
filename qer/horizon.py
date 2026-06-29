"""Quantum exposure horizon — turning HNDL into years, via Mosca's inequality.

A 0-100 HNDL score tells you *which* endpoints to fix first. It does not tell an
executive *how exposed they already are*. This module does, by making Mosca's
inequality concrete and dated:

    (data shelf life X) + (migration time Y)  >  (years until a CRQC exists Z)
        => data encrypted today is decryptable before you can protect it.

The overhang ``X + Y - Z`` is the **shortfall in years**: how far past the
"should-have-started-migrating" date you already are for a given endpoint. We
also surface the concrete *start-by year* (``crqc_year - shelf_life -
migration_time``) — the deadline a board can act on.

CRQC arrival is uncertain, so the horizon is computed against a named, *citable*
scenario (drawn from expert-survey ranges such as the Global Risk Institute
Quantum Threat Timeline and Mosca's own estimates). The scenario is explicit in
every output so no single guess is smuggled in as fact.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .models import AssetProfile, Finding, QuantumRisk, Severity

REF_MOSCA = "https://eprint.iacr.org/2015/1075"
REF_GRI_TIMELINE = "https://globalriskinstitute.org/publication/2023-quantum-threat-timeline-report/"
REF_NIST_PQC = "https://csrc.nist.gov/projects/post-quantum-cryptography"


@dataclass(frozen=True)
class Scenario:
    name: str
    crqc_year: int
    note: str


# Defender-facing planning scenarios for when a cryptographically relevant
# quantum computer (able to break RSA-2048 / 256-bit ECC) first exists. These are
# planning assumptions, not predictions — the earlier ones are prudent lower
# bounds, not forecasts.
SCENARIOS: dict[str, Scenario] = {
    "aggressive": Scenario("aggressive", 2030,
                           "Early-arrival planning bound (lower tail of expert estimates)."),
    "baseline": Scenario("baseline", 2035,
                         "Median expert estimate (~10-15 year horizon)."),
    "conservative": Scenario("conservative", 2040,
                             "Later-arrival planning bound (upper expert estimates)."),
}
DEFAULT_SCENARIO = "baseline"

# crypto_agility (1..5) -> estimated years to complete migration of that asset.
_MIGRATION_YEARS = {5: 1.0, 4: 2.0, 3: 3.0, 2: 5.0, 1: 7.0}


def migration_years(crypto_agility: int) -> float:
    return _MIGRATION_YEARS.get(int(crypto_agility), 3.0)


def get_scenario(name: Optional[str]) -> Scenario:
    return SCENARIOS.get((name or DEFAULT_SCENARIO).strip().lower(), SCENARIOS[DEFAULT_SCENARIO])


def mosca_shortfall(shelf_life_years: float, migration_yrs: float,
                    years_to_crqc: float) -> float:
    """Mosca's overhang: X + Y - Z. Positive => exposed today."""
    return shelf_life_years + migration_yrs - years_to_crqc


@dataclass
class AssetHorizon:
    host: str
    port: int
    hndl_relevant: bool
    shelf_life_years: int
    migration_years: float
    years_to_crqc: float
    crqc_year: int
    scenario: str
    shortfall_years: float          # X + Y - Z
    exposure_years: float           # max(0, shortfall)
    start_by_year: int              # crqc_year - shelf_life - migration (migrate-start deadline)
    complete_by_year: int           # crqc_year - shelf_life (vulnerable-crypto cutover)
    verdict: str                    # exposed | margin | clear | n/a

    @property
    def years_behind(self) -> float:
        """How many years past the start-by deadline we already are (>=0)."""
        return max(0.0, self.exposure_years)


def assess(profile: AssetProfile, hndl_relevant: bool, current_year: int,
           scenario: Optional[str] = None, crqc_year: Optional[int] = None) -> AssetHorizon:
    sc = get_scenario(scenario)
    if crqc_year is not None:               # explicit year overrides the named scenario
        sc = Scenario(f"custom({crqc_year})", int(crqc_year), "Operator-supplied CRQC year.")
    years_to_crqc = float(sc.crqc_year - current_year)
    mig = migration_years(profile.crypto_agility)
    shelf = float(profile.shelf_life_years)
    shortfall = mosca_shortfall(shelf, mig, years_to_crqc)

    if not hndl_relevant:
        verdict = "n/a"
    elif shortfall > 0:
        verdict = "exposed"
    elif shortfall >= -3:
        verdict = "margin"
    else:
        verdict = "clear"

    return AssetHorizon(
        host=profile.host, port=profile.port, hndl_relevant=hndl_relevant,
        shelf_life_years=profile.shelf_life_years, migration_years=mig,
        years_to_crqc=years_to_crqc, crqc_year=sc.crqc_year, scenario=sc.name,
        shortfall_years=round(shortfall, 1),
        exposure_years=round(max(0.0, shortfall), 1),
        start_by_year=int(round(sc.crqc_year - shelf - mig)),
        complete_by_year=int(round(sc.crqc_year - shelf)),
        verdict=verdict)


def _severity(shortfall: float) -> Severity:
    if shortfall >= 7:
        return Severity.HIGH
    if shortfall >= 3:
        return Severity.MEDIUM
    return Severity.LOW


def horizon_finding(h: AssetHorizon) -> Optional[Finding]:
    """A finding for an endpoint whose data outlives the quantum horizon, so it
    flows into every SIEM/CBOM exporter alongside the other findings."""
    if h.verdict != "exposed":
        return None
    start_phrase = (f"the migration start-by date was {h.start_by_year}"
                    if h.start_by_year < (h.crqc_year - h.years_to_crqc)
                    else f"migration must start by {h.start_by_year}")
    return Finding(
        id="QER-HORIZON",
        title=f"Data outlives the quantum horizon by {h.exposure_years:g} year(s)",
        severity=_severity(h.shortfall_years), quantum_risk=QuantumRisk.QUANTUM_VULNERABLE,
        category="horizon", host=h.host, port=h.port,
        description=(
            f"Under the '{h.scenario}' scenario (CRQC ~{h.crqc_year}), this endpoint's "
            f"{h.shelf_life_years}-year data shelf life plus an estimated {h.migration_years:g}-year "
            f"migration exceeds the {h.years_to_crqc:g} years until a quantum computer exists. By "
            f"Mosca's inequality, traffic harvested today is decryptable before it stops being secret — "
            f"{start_phrase}, so vulnerable crypto must be retired by {h.complete_by_year}."),
        evidence=(f"shelf_life={h.shelf_life_years}y + migration={h.migration_years:g}y "
                  f"- years_to_crqc={h.years_to_crqc:g}y = shortfall {h.shortfall_years:g}y"),
        recommendation=(f"Begin PQ migration of this channel now; you are effectively "
                        f"{h.exposure_years:g} year(s) past the prudent start date."),
        references=[REF_MOSCA, REF_GRI_TIMELINE, REF_NIST_PQC])


@dataclass
class FleetHorizon:
    scenario: str
    crqc_year: int
    assessed: int
    hndl_relevant: int
    exposed: int
    worst_shortfall_years: float
    earliest_start_by_year: Optional[int]
    median_exposure_years: float


def _median(values: list[float]) -> float:
    s = sorted(values)
    n = len(s)
    if n == 0:
        return 0.0
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2.0


def fleet_horizon(items: list[AssetHorizon]) -> FleetHorizon:
    relevant = [h for h in items if h.hndl_relevant]
    exposed = [h for h in relevant if h.verdict == "exposed"]
    worst = max((h.shortfall_years for h in relevant), default=0.0)
    starts = [h.start_by_year for h in exposed]
    median = _median([h.exposure_years for h in exposed])
    sc = items[0] if items else None
    return FleetHorizon(
        scenario=sc.scenario if sc else DEFAULT_SCENARIO,
        crqc_year=sc.crqc_year if sc else SCENARIOS[DEFAULT_SCENARIO].crqc_year,
        assessed=len(items), hndl_relevant=len(relevant), exposed=len(exposed),
        worst_shortfall_years=round(worst, 1),
        earliest_start_by_year=min(starts) if starts else None,
        median_exposure_years=round(median, 1))


def to_serializable_fleet(f: FleetHorizon) -> dict:
    return {
        "scenario": f.scenario, "crqc_year": f.crqc_year, "assessed": f.assessed,
        "hndl_relevant": f.hndl_relevant, "exposed": f.exposed,
        "worst_shortfall_years": f.worst_shortfall_years,
        "earliest_start_by_year": f.earliest_start_by_year,
        "median_exposure_years": f.median_exposure_years,
    }
