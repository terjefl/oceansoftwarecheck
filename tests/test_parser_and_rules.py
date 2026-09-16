"""Tests against the real OLP format.

Fixtures built on one real OceanLink Pro report (2026-08-28, a Fisker Ocean
One, a real "zebra": everything at 2.1 level except BCM):

- `olp_report.pdf`: the PDF exactly as exported by the OLP app, unmodified
  (the owner chose to keep the real VIN). This is what members upload, so it
  exercises the pdfplumber text-extraction step with the app's real layout.
- `olp_report.txt`: its text extraction with the VIN replaced, used by the
  many tests that mutate module values.
- `olp_report_21_full.txt`, `olp_report_22_full.txt`, `olp_report_marlin.txt`,
  `olp_report_marlin_bcm41.txt`: synthetic reference cars derived from it
  (100% 2.1, full 2.2, on Marlin, on Marlin with BCM 41).
"""

from pathlib import Path

import pytest

from app.parser import ReportParseError, parse_report
from app.rules import (
    MISSING,
    OK,
    OUTDATED,
    VERDICT_READY,
    VERDICT_ZEBRA,
    RequirementsValidationError,
    evaluate,
    load_requirements,
    parse_requirements_text,
)

FIXTURES = Path(__file__).parent / "fixtures"
REQUIREMENTS = Path(__file__).parent.parent / "requirements.example.yaml"


def _report():
    return parse_report((FIXTURES / "olp_report.txt").read_bytes(), "olp_report.txt")


def test_parse_real_format():
    report = _report()
    assert report.vin == "VCF1ZBE20PG099999"
    assert report.meta["report_date"].startswith("2026-08-28")

    by_code = {m.code: m for m in report.modules}
    assert len(report.modules) == 37
    assert by_code["GW"].supplier_sw == "GW500002"
    assert by_code["GW"].section == "BODY"
    assert by_code["GW"].name == "Gateway"
    assert by_code["VCU"].supplier_sw == "VCU039021"
    assert by_code["VCU"].section == "POWERTRAIN"
    assert by_code["ECC"].supplier_sw == "ECC395 24"
    assert by_code["MCU_F"].supplier_sw == "MCU5000019"
    assert by_code["IBS"].supplier_sw == "88211V040000420131"
    assert by_code["EPS1"].supplier_sw == "EPS395001"  # leading whitespace trimmed
    assert by_code["HYDRA"].section == "ADAS"
    assert by_code["ESP"].software == "FM292045S020J"
    assert by_code["ESP"].bootloader == "FM292045B020B"


def test_parse_real_olp_pdf_end_to_end():
    """The real PDF from the OLP app must extract to exactly the module list of
    the text fixture and get the same verdict. A layout change in the app or a
    pdfplumber upgrade that reads the report differently fails here."""
    pdf_report = parse_report((FIXTURES / "olp_report.pdf").read_bytes(), "olp_report.pdf")
    text_report = _report()
    assert pdf_report.vin == "VCF1ZBE21PG002387"
    assert pdf_report.meta["report_date"].startswith("2026-08-28 18:15:16")
    assert len(pdf_report.modules) == 37
    assert [(m.code, m.name, m.section, m.supplier_sw, m.software, m.hardware, m.bootloader)
            for m in pdf_report.modules] == [
        (m.code, m.name, m.section, m.supplier_sw, m.software, m.hardware, m.bootloader)
        for m in text_report.modules
    ]

    evaluation = evaluate(pdf_report, load_requirements(REQUIREMENTS))
    assert evaluation.verdict == VERDICT_ZEBRA
    assert (evaluation.trim, evaluation.trim_name) == ("Z", "One")
    assert {r.requirement.id for r in evaluation.failing_critical} == {"BCM"}


def test_parse_pdf_roundtrip(tmp_path):
    """The PDF path: render the fixture to PDF and parse it back."""
    weasyprint = pytest.importorskip("weasyprint")
    text = (FIXTURES / "olp_report.txt").read_text()
    html = "<pre style='font-family: monospace'>" + text + "</pre>"
    pdf_bytes = weasyprint.HTML(string=html).write_pdf()

    report = parse_report(pdf_bytes, "report.pdf")
    assert report.vin == "VCF1ZBE20PG099999"
    assert len(report.modules) == 37


def test_parse_rejects_garbage():
    with pytest.raises(ReportParseError):
        parse_report(b"not a report at all")
    with pytest.raises(ReportParseError):
        parse_report(b"")
    # Correct heading but no VIN
    with pytest.raises(ReportParseError):
        parse_report(b"ECU Software Version Report\nGW - Gateway\n")


def test_evaluate_zebra_car():
    """With the corrected V2-workbook numbers, the fixture car (a One trim)
    meets 2.1 on everything except BCM (21 < 30)."""
    requirements = load_requirements(REQUIREMENTS)
    evaluation = evaluate(_report(), requirements)

    by_id = {r.requirement.id: r for r in evaluation.results}
    assert by_id["ECC"].status == OK and by_id["ECC"].extracted == 24
    assert by_id["BMS"].status == OK and by_id["BMS"].extracted == 21
    assert by_id["BMS"].variant == "NMC (One/Extreme/Ultra)"
    assert by_id["VCU"].status == OK and by_id["VCU"].level == "2.1"
    assert by_id["MCU_F"].status == OK and by_id["MCU_F"].extracted == 19
    assert by_id["MCU_R"].status == OK
    assert by_id["ESP"].status == OK
    assert (by_id["ESP"].extracted, by_id["ESP"].required) == (402, 401)
    # BCM 21 is below even the 2.0 level (30)
    assert by_id["BCM"].status == OUTDATED
    assert (by_id["BCM"].extracted, by_id["BCM"].required, by_id["BCM"].level) == (21, 30, None)

    assert evaluation.verdict == VERDICT_ZEBRA
    assert {r.requirement.id for r in evaluation.failing_critical} == {"BCM"}
    # 37 modules in the report, 8 with requirements -> 29 without
    assert len(evaluation.extra_modules) == 29


def test_evaluate_full_21_car():
    """Lift BCM (the only failing module) to 2.1 level -> directly Marlin-ready."""
    requirements = load_requirements(REQUIREMENTS)
    report = _report()
    for module in report.modules:
        if module.code == "BCM":
            module.supplier_sw = "BCM395030"
    evaluation = evaluate(report, requirements)
    assert evaluation.verdict == VERDICT_READY
    assert all(r.status == OK for r in evaluation.results)
    # Jens' note 2: a direct 2.1->Marlin jump leaves the 2.2-only ECUs behind.
    # This car meets 2.1 but not 2.2 on BCM (30<42), ESP (402<501), IBS (400<401),
    # ECC (24<25), MCU_F/R (19<21) and VCU (21<23); only BMS (21) already meets 2.2.
    assert {r.requirement.id for r in evaluation.ok_below_top} == {
        "BCM", "ESP", "IBS", "ECC", "MCU_F", "MCU_R", "VCU",
    }


def test_sport_trim_variants_and_missing_rear_mcu():
    """A Sport (VIN trim letter S): LFP BMS (BMSL39015) is OK via its variant,
    and the absent MCU_R is not treated as missing."""
    requirements = load_requirements(REQUIREMENTS)
    report = _report()
    report.vin = report.vin[:4] + "S" + report.vin[5:]
    report.modules = [m for m in report.modules if m.code != "MCU_R"]
    for module in report.modules:
        if module.code == "BMS":
            module.supplier_sw = "BMSL39015"
        if module.code == "BCM":
            module.supplier_sw = "BCM395030"
    evaluation = evaluate(report, requirements)

    by_id = {r.requirement.id: r for r in evaluation.results}
    assert "MCU_R" not in by_id  # not required for Sport
    assert by_id["BMS"].status == OK
    assert (by_id["BMS"].extracted, by_id["BMS"].required) == (15, 15)
    assert by_id["BMS"].variant == "LFP (Sport)"
    assert evaluation.verdict == VERDICT_READY

    # ...but on an Extreme (E), a missing MCU_R is still a failure
    report.vin = report.vin[:4] + "E" + report.vin[5:]
    evaluation = evaluate(report, requirements)
    by_id = {r.requirement.id: r for r in evaluation.results}
    assert by_id["MCU_R"].status == MISSING
    assert evaluation.verdict == VERDICT_ZEBRA


def test_ecc_alternate_format_and_unknown_bms_line():
    """ECC appears both as "ECC395 24" and "ECC39519"; an unknown BMS software
    line (neither BMSN nor BMSL) must surface as unparseable, not as a pass."""
    requirements = load_requirements(REQUIREMENTS)
    report = _report()
    for module in report.modules:
        if module.code == "ECC":
            module.supplier_sw = "ECC39519"  # 2.0-level, no-space form
        if module.code == "BMS":
            module.supplier_sw = "BMSX99999"
    evaluation = evaluate(report, requirements)
    by_id = {r.requirement.id: r for r in evaluation.results}
    assert by_id["ECC"].status == OUTDATED
    assert (by_id["ECC"].extracted, by_id["ECC"].required) == (19, 24)
    assert by_id["BMS"].status == "unparseable"


def test_missing_critical_module_gives_zebra():
    requirements = load_requirements(REQUIREMENTS)
    report = _report()
    report.modules = [m for m in report.modules if m.code != "BMS"]
    evaluation = evaluate(report, requirements)
    assert evaluation.verdict == VERDICT_ZEBRA
    by_id = {r.requirement.id: r for r in evaluation.results}
    assert by_id["BMS"].status == MISSING


def test_unknown_trim_letter_still_requires_rear_mcu():
    """A VIN whose 5th character is not a known trim letter must NOT exempt
    MCU_R: treating an unknown trim as 'Sport-like' would let a two-motor car
    with a missing rear MCU pass as Marlin-ready."""
    requirements = load_requirements(REQUIREMENTS)
    report = _report()
    report.vin = report.vin[:4] + "X" + report.vin[5:]
    report.modules = [m for m in report.modules if m.code != "MCU_R"]
    for module in report.modules:
        if module.code == "BCM":
            module.supplier_sw = "BCM395030"
    evaluation = evaluate(report, requirements)

    assert evaluation.trim == "X" and evaluation.trim_name == ""
    by_id = {r.requirement.id: r for r in evaluation.results}
    assert by_id["MCU_R"].status == MISSING
    assert evaluation.verdict == VERDICT_ZEBRA

    # ...whereas a known One (Z) exposes trim name and passes with MCU_R present
    evaluation = evaluate(_report(), requirements)
    assert (evaluation.trim, evaluation.trim_name) == ("Z", "One")


def test_pdf_with_too_many_pages_is_rejected():
    """Text extraction is CPU-bound and linear in page count; a PDF far larger
    than any real OLP report is rejected before extraction starts."""
    weasyprint = pytest.importorskip("weasyprint")
    from app.parser import MAX_REPORT_PAGES

    html = "".join(
        f"<p style='page-break-after: always'>page {i}</p>" for i in range(MAX_REPORT_PAGES + 5)
    )
    pdf_bytes = weasyprint.HTML(string=html).write_pdf()
    with pytest.raises(ReportParseError) as excinfo:
        parse_report(pdf_bytes, "big.pdf")
    assert excinfo.value.key == "too_many_pages"


_MINIMAL = """
version: t
profiles: ["2.0", "2.1", "2.2"]
target_profile: "2.1"
modules:
  - id: VCU
    match: [VCU]
    extract: 'VCU\\d{3}0*(\\d+)$'
    levels: {"2.0": 20, "2.1": 21}
"""


def test_requirements_validation_rejects_wrong_types():
    """A bare string for `match` used to be iterated character by character
    (VCU -> V, C, U) and silently marked the module missing on every car."""
    cases = {
        "match: [VCU]": ("match: VCU", "`match` must be a non-empty list"),
        'levels: {"2.0": 20, "2.1": 21}': ('levels: {"2.0": 20, "2.1": "21a"}', "must be an integer"),
        "    extract: 'VCU": ("    variants: nope\n    extract: 'VCU", "`variants` must be a list"),
        'profiles: ["2.0", "2.1", "2.2"]': ('profiles: "2.0, 2.1"', "`profiles` must be a non-empty list"),
        "  - id: VCU\n    match: [VCU]": ("  - VCU\n  - match: [VCU]", "must be a mapping"),
    }
    for original, (replacement, message) in cases.items():
        text = _MINIMAL.replace(original, replacement)
        assert text != _MINIMAL
        with pytest.raises(RequirementsValidationError) as excinfo:
            parse_requirements_text(text)
        assert message in str(excinfo.value), (replacement, str(excinfo.value))
    # And the unmodified minimal file is fine
    assert parse_requirements_text(_MINIMAL).modules[0].match == ["VCU"]


def test_ok_below_top_only_lists_modules_with_a_top_level():
    """A module that defines no level for the highest profile cannot be
    'left behind by 2.2' and must not appear in that list."""
    requirements = parse_requirements_text(_MINIMAL)  # VCU has no 2.2 level
    evaluation = evaluate(_report(), requirements)
    assert evaluation.verdict == VERDICT_READY
    assert evaluation.ok_below_top == []

    with_top = parse_requirements_text(_MINIMAL.replace('"2.1": 21}', '"2.1": 21, "2.2": 23}'))
    evaluation = evaluate(_report(), with_top)  # VCU039021 -> 21 < 23
    assert [r.requirement.id for r in evaluation.ok_below_top] == ["VCU"]
    assert evaluation.results[0].top_required == 23


def _fixture_report(name: str):
    return parse_report((FIXTURES / name).read_bytes(), name)


def test_reference_cars_from_the_fleet():
    """Module values observed on real consented uploads (Sep 2026), applied to
    the fixture report: a 100% 2.1 car, a full 2.2 car and two Marlin cars.
    These pin the verdicts the association saw and agreed with."""
    requirements = load_requirements(REQUIREMENTS)

    full_21 = evaluate(_fixture_report("olp_report_21_full.txt"), requirements)
    assert full_21.verdict == VERDICT_READY
    assert all(r.status == OK for r in full_21.results)
    # Every module exactly at the 2.1 minimum -> all seven 2.2-only ECUs are left behind
    assert {r.requirement.id for r in full_21.ok_below_top} == {"BCM", "ESP", "IBS", "ECC", "MCU_F", "MCU_R", "VCU"}

    full_22 = evaluate(_fixture_report("olp_report_22_full.txt"), requirements)
    assert full_22.verdict == VERDICT_READY
    assert full_22.ok_below_top == []
    assert {r.requirement.id: r.level for r in full_22.results} == {
        m: "2.2" for m in ["BCM", "ESP", "IBS", "ECC", "BMS", "MCU_R", "MCU_F", "VCU"]
    }


def test_car_already_on_marlin_gets_marlin_verdict_not_ready():
    """VCU 24 (= VCU 2.4) only exists on Marlin cars. Such a car must not be
    told it 'can be updated to Marlin' (or worse, that it is a zebra); it gets
    the informational 'already on Marlin' verdict and a list of what Marlin
    left below the 2.2 level."""
    from app.rules import VERDICT_MARLIN

    requirements = load_requirements(REQUIREMENTS)

    marlin = evaluate(_fixture_report("olp_report_marlin.txt"), requirements)
    assert marlin.verdict == VERDICT_MARLIN
    assert marlin.below_top == []
    by_id = {r.requirement.id: r for r in marlin.results}
    assert by_id["VCU"].extracted == 24 and by_id["VCU"].requirement.marlin_level == 24

    bcm41 = evaluate(_fixture_report("olp_report_marlin_bcm41.txt"), requirements)
    assert bcm41.verdict == VERDICT_MARLIN
    assert [(r.requirement.id, r.extracted, r.top_required) for r in bcm41.below_top] == [("BCM", 41, 42)]

    # A Marlin car with a failing critical module is still "on Marlin", not a zebra
    report = _fixture_report("olp_report_marlin.txt")
    report.modules = [m for m in report.modules if m.code != "BMS"]
    assert evaluate(report, requirements).verdict == VERDICT_MARLIN

    # VCU below the marker -> ordinary readiness logic applies
    report = _fixture_report("olp_report_marlin.txt")
    for m in report.modules:
        if m.code == "VCU":
            m.supplier_sw = "VCU039023"
    assert evaluate(report, requirements).verdict == VERDICT_READY

    # Without any marlin_level in the file, no car can be "on Marlin"
    plain = parse_requirements_text(REQUIREMENTS.read_text().replace("marlin_level: 24", "", 1))  # the VCU module marker, not marlin_modules
    assert all(m.marlin_level is None for m in plain.modules)
    assert evaluate(_fixture_report("olp_report_marlin.txt"), plain).verdict == VERDICT_READY


def test_marlin_level_must_be_an_integer():
    with pytest.raises(RequirementsValidationError) as excinfo:
        parse_requirements_text(REQUIREMENTS.read_text().replace("marlin_level: 24", "marlin_level: soon", 1))
    assert "marlin_level" in str(excinfo.value)


def test_duplicate_ecu_block_stays_visible_as_extra_module():
    """Two blocks with the same code: the first is evaluated, the second must
    show up under 'other modules' instead of vanishing."""
    import copy

    requirements = load_requirements(REQUIREMENTS)
    report = _report()
    bms = next(m for m in report.modules if m.code == "BMS")
    duplicate = copy.copy(bms)
    duplicate.supplier_sw = "BMSN39001"
    report.modules.append(duplicate)
    evaluation = evaluate(report, requirements)
    assert next(r for r in evaluation.results if r.requirement.id == "BMS").version == "BMSN39021"
    assert any(m.supplier_sw == "BMSN39001" for m in evaluation.extra_modules)
    assert len(evaluation.extra_modules) == 30


def test_variant_levels_override_per_profile_not_wholesale():
    """A variant that only sets the 2.2 level keeps the module's 2.1 level;
    it used to replace the whole mapping and produce 'unparseable'."""
    text = _MINIMAL.replace(
        'levels: {"2.0": 20, "2.1": 21}',
        'levels: {"2.0": 20, "2.1": 21}\n    variants:\n      - name: X\n        pattern: "^VCU"\n        levels: {"2.2": 23}',
    )
    requirements = parse_requirements_text(text)
    result = evaluate(_report(), requirements).results[0]
    assert (result.variant, result.status, result.required, result.top_required) == ("X", OK, 21, 23)


def test_empty_supplier_version_gets_its_own_status():
    from app.rules import EMPTY

    requirements = load_requirements(REQUIREMENTS)
    report = _report()
    for m in report.modules:
        if m.code == "VCU":
            m.supplier_sw = "   "
    evaluation = evaluate(report, requirements)
    vcu = next(r for r in evaluation.results if r.requirement.id == "VCU")
    assert vcu.status == EMPTY and vcu.required == 21
    assert evaluation.verdict == VERDICT_ZEBRA


def test_notes_field_is_parsed_and_must_be_a_string():
    requirements = load_requirements(REQUIREMENTS)
    assert "Open points" in requirements.notes
    with pytest.raises(RequirementsValidationError):
        parse_requirements_text(_MINIMAL + "notes: [not, a, string]\n")


# --- Outcome classification (the association's five categories, Sep 2026) ---

def _with(report, **values):
    """Replace Supplier SW Version on the given ECU codes."""
    for m in report.modules:
        if m.code in values:
            m.supplier_sw = values[m.code]
    return report


def test_outcomes_for_the_reference_cars():
    from app.rules import (
        OUTCOME_FULL_TARGET,
        OUTCOME_FULL_TOP,
        OUTCOME_MARLIN,
        OUTCOME_ZEBRA_TARGET,
        OUTCOME_ZEBRA_TOP,
    )

    requirements = load_requirements(REQUIREMENTS)

    full_21 = evaluate(_fixture_report("olp_report_21_full.txt"), requirements)
    assert (full_21.outcome, full_21.complete_profile, full_21.top_evidence) == (
        OUTCOME_FULL_TARGET, "2.1", "2.1"
    )
    assert {r.requirement.id for r in full_21.below("2.2")} == {"BCM", "ESP", "IBS", "ECC", "MCU_F", "MCU_R", "VCU"}
    assert full_21.below("2.1") == []

    full_22 = evaluate(_fixture_report("olp_report_22_full.txt"), requirements)
    assert (full_22.outcome, full_22.complete_profile, full_22.top_evidence) == (
        OUTCOME_FULL_TOP, "2.2", "2.2"
    )
    assert full_22.below("2.2") == []

    # The real fixture car: BCM 21 is below even 2.0 -> not Marlin-ready
    zebra = evaluate(_report(), requirements)
    assert zebra.outcome == OUTCOME_ZEBRA_TARGET
    assert zebra.complete_profile is None
    assert [r.requirement.id for r in zebra.below("2.1")] == ["BCM"]
    assert zebra.verdict == VERDICT_ZEBRA

    # A started-but-incomplete 2.2: BCM and VCU already at 2.2, ECC/MCU/ESP/IBS still 2.1
    started = _with(_fixture_report("olp_report_21_full.txt"), BCM="BCM395042", VCU="VCU039023")
    started = evaluate(started, requirements)
    assert (started.outcome, started.complete_profile, started.top_evidence) == (
        OUTCOME_ZEBRA_TOP, "2.1", "2.2"
    )
    assert {r.requirement.id for r in started.below("2.2")} == {"ECC", "ESP", "IBS", "MCU_F", "MCU_R"}
    assert started.verdict == VERDICT_READY  # still Marlin-capable in the old sense

    marlin = evaluate(_fixture_report("olp_report_marlin.txt"), requirements)
    assert marlin.outcome == OUTCOME_MARLIN


def test_shared_minimums_are_not_evidence_of_the_higher_profile():
    """BMS is 21 on every profile and BCM 30 on both 2.0 and 2.1: such readings
    must not count as evidence of the higher profile, so a clean 2.1 car is not
    turned into a '2.2 zebra'. ECC 24 is the 2.1 level (2.2 is 25 since
    2026-09-14), so it is evidence of 2.1 only."""
    from app.rules import OUTCOME_FULL_TARGET

    requirements = load_requirements(REQUIREMENTS)
    evaluation = evaluate(_fixture_report("olp_report_21_full.txt"), requirements)
    by_id = {r.requirement.id: r for r in evaluation.results}
    assert by_id["ECC"].level == "2.1" and by_id["ECC"].evidence_level == "2.1"
    assert by_id["BMS"].level == "2.2" and by_id["BMS"].evidence_level == "2.0"
    assert by_id["BCM"].level == "2.1" and by_id["BCM"].evidence_level == "2.0"
    assert by_id["VCU"].level == "2.1" and by_id["VCU"].evidence_level == "2.1"
    assert by_id["VCU"].meets == {"2.0": True, "2.1": True, "2.2": False}
    assert evaluation.outcome == OUTCOME_FULL_TARGET


def test_pure_20_car_and_missing_module_are_below_target():
    from app.rules import OUTCOME_ZEBRA_TARGET

    requirements = load_requirements(REQUIREMENTS)
    pure_20 = _with(
        _fixture_report("olp_report_21_full.txt"),
        ECC="ECC39519", MCU_F="MCU5000017", MCU_R="MCU5000017", VCU="VCU039020",
    )
    pure_20 = evaluate(pure_20, requirements)
    assert (pure_20.outcome, pure_20.complete_profile, pure_20.top_evidence) == (
        OUTCOME_ZEBRA_TARGET, "2.0", "2.0"
    )

    report = _fixture_report("olp_report_22_full.txt")
    report.modules = [m for m in report.modules if m.code != "ESP"]
    missing = evaluate(report, requirements)
    assert missing.outcome == OUTCOME_ZEBRA_TARGET and missing.complete_profile is None
    by_id = {r.requirement.id: r for r in missing.results}
    assert by_id["ESP"].meets == {"2.0": False, "2.1": False, "2.2": False}


def test_sport_without_rear_mcu_can_still_be_complete():
    from app.rules import OUTCOME_FULL_TOP

    requirements = load_requirements(REQUIREMENTS)
    report = _fixture_report("olp_report_22_full.txt")
    report.vin = report.vin[:4] + "S" + report.vin[5:]
    report.modules = [m for m in report.modules if m.code != "MCU_R"]
    _with(report, BMS="BMSL39015")
    evaluation = evaluate(report, requirements)
    assert evaluation.outcome == OUTCOME_FULL_TOP
    assert "MCU_R" not in {r.requirement.id for r in evaluation.results}


def test_ibooster_must_follow_esp_to_the_22_generation():
    """ESP and iBooster are Bosch units flashed together: a car with ESP at the
    2.2 level but iBooster still on the 2.1 line (400) is a 2.2 zebra with IBS in
    the below-2.2 list; iBooster 401 makes it full 2.2. The Marlin requirement
    (400) is met by every car, so nothing loses Marlin readiness."""
    from app.rules import OUTCOME_FULL_TOP, OUTCOME_ZEBRA_TOP

    requirements = load_requirements(REQUIREMENTS)
    stale = _with(_fixture_report("olp_report_22_full.txt"), IBS="88211V040000420131")
    evaluation = evaluate(stale, requirements)
    assert evaluation.outcome == OUTCOME_ZEBRA_TOP
    assert [r.requirement.id for r in evaluation.below_top] == ["IBS"]
    ibs = next(r for r in evaluation.results if r.requirement.id == "IBS")
    assert (ibs.extracted, ibs.meets["2.1"], ibs.meets["2.2"]) == (400, True, False)

    fresh = evaluate(_fixture_report("olp_report_22_full.txt"), requirements)
    assert fresh.outcome == OUTCOME_FULL_TOP
    assert next(r for r in fresh.results if r.requirement.id == "IBS").extracted == 401


def test_marlin_package_completeness():
    """`marlin_modules` says whether a Marlin car got the whole Marlin package
    (VCU 24, PDU 4000, FCM PSOP09, HYDRA ADAS039051). It never changes the
    outcome or the module counts, and doubt never gives ok."""
    requirements = load_requirements(REQUIREMENTS)
    assert [m.id for m in requirements.marlin_modules] == ["VCU", "PDU", "FCM", "HYDRA"]

    full = evaluate(_fixture_report("olp_report_marlin.txt"), requirements)
    assert full.outcome == "marlin" and full.marlin_complete and full.marlin_below == []
    assert [(r.requirement.id, r.extracted) for r in full.marlin_results] == [("VCU", 24), ("PDU", 4000), ("FCM", 9), ("HYDRA", 51)]

    partial = evaluate(_fixture_report("olp_report_marlin_bcm41.txt"), requirements)
    assert partial.outcome == "marlin" and not partial.marlin_complete
    assert [(r.requirement.id, r.extracted, r.status) for r in partial.marlin_below] == [
        ("PDU", 3900, "outdated"), ("FCM", 0, "outdated"), ("HYDRA", 17, "outdated"),
    ]
    assert len(partial.results) == 8 and len(partial.extra_modules) == 29  # unchanged by marlin_modules

    missing = _with(_fixture_report("olp_report_marlin.txt"), FCM="weird")
    missing.modules = [m for m in missing.modules if m.code != "PDU"]
    ev = evaluate(missing, requirements)
    assert [(r.requirement.id, r.status) for r in ev.marlin_below] == [("PDU", "missing"), ("FCM", "unparseable")]

    for bad in ['marlin_modules: {}', 'marlin_modules: [{id: X, marlin_level: "a"}]', 'marlin_modules: [{id: X, marlin_level: 1, extract: "nogroup"}]']:
        with pytest.raises(RequirementsValidationError):
            parse_requirements_text(REQUIREMENTS.read_text().split("\nmarlin_modules:")[0] + "\n" + bad + "\n")


def test_parse_older_olp_label_and_cid_padding():
    """Reports from mid-2025 OLP builds say 'Supplier Software Version' and pad
    empty fields with glyphs pdfplumber renders as (cid:0)."""
    from app.parser import parse_report

    text = (
        "OceanLink Pro\nECU Software Version Report\nDate: 2025-06-20 11:37:55\nVIN: VCF1ZBE20PG099999\n"
        "BODY\nBCM - Body Control Module\nSoftware Version: FM298033S001L\nHardware Version: FM298033H001E\n"
        "Supplier Software Version: BCM395030\nBootloader Version: 0108(cid:0)(cid:0)\n"
        "OHC - Overhead Console\nSoftware Version: FM297026S042H\nHardware Version: FM297026H042G\n"
        "Supplier Software Version: OHC390006\nBootloader Version: (cid:0)(cid:0)(cid:0)\n"
    )
    report = parse_report(text.encode())
    by_code = {m.code: m for m in report.modules}
    assert by_code["BCM"].supplier_sw == "BCM395030" and by_code["BCM"].bootloader == "0108"
    assert by_code["OHC"].supplier_sw == "OHC390006" and by_code["OHC"].bootloader == ""


def test_na_counts_as_empty_field():
    """OLP writes NA when a module gave no answer; the check treats it as an
    empty field (status 'empty'), not as an unrecognised version."""
    from app.parser import parse_report

    text = (
        "OceanLink Pro\nECU Software Version Report\nDate: 2026-01-01\nVIN: VCF1ZBE20PG099999\n"
        "BODY\nECC - Electrical Climate Controller\nSoftware Version: NA\nHardware Version: NA\n"
        "Supplier SW Version: NA\nBootloader Version: NA\n"
    )
    ecc = parse_report(text.encode()).modules[0]
    assert (ecc.supplier_sw, ecc.software, ecc.hardware, ecc.bootloader) == ("", "", "", "")
    only_punctuation = text.replace("Supplier SW Version: NA", "Supplier SW Version: )))")
    assert parse_report(only_punctuation.encode()).modules[0].supplier_sw == ""
