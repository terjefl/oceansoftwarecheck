"""The vehicle register: schema migration of a pre-v2 database, re-evaluation
of stored reports against the current requirements, and deletion per VIN."""

import sqlite3
from pathlib import Path

from app.db import Database
from app.parser import parse_report
from app.rules import evaluate, load_requirements

FIXTURES = Path(__file__).parent / "fixtures"
REQUIREMENTS = Path(__file__).parent.parent / "requirements.example.yaml"

# The schema as shipped in the consent period (before Sep 2026), verbatim.
OLD_SCHEMA = """
CREATE TABLE submissions (
    id TEXT PRIMARY KEY, vin TEXT NOT NULL, vin_hash TEXT NOT NULL,
    uploaded_at TEXT NOT NULL, verdict TEXT NOT NULL,
    requirements_version TEXT NOT NULL, lang TEXT NOT NULL DEFAULT 'en',
    stored_filename TEXT
);
CREATE TABLE module_readings (
    submission_id TEXT NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
    module_id TEXT, raw_name TEXT NOT NULL, version TEXT NOT NULL, status TEXT NOT NULL
);
"""


def _old_database(path: Path, report_name: str, vin: str) -> None:
    """Writes a consent-era database with one submission, the way v1 stored it."""
    report = parse_report((FIXTURES / report_name).read_bytes(), report_name)
    conn = sqlite3.connect(path)
    conn.executescript(OLD_SCHEMA)
    conn.execute(
        "INSERT INTO submissions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("old1", vin, "hash-" + vin, "2026-09-01T10:00:00+00:00", "ready", "old", "en", None),
    )
    conn.executemany(
        "INSERT INTO module_readings VALUES (?, ?, ?, ?, ?)",
        [("old1", None, m.raw_name, m.supplier_sw, "extra") for m in report.modules],
    )
    conn.commit()
    conn.close()


def test_old_database_is_migrated_and_backfilled_by_reevaluation(tmp_path):
    path = tmp_path / "oceansoftwarecheck.sqlite3"
    _old_database(path, "olp_report_22_full.txt", "VCF1ZBE20PG099997")

    db = Database(path)  # migration runs here
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(submissions)")}
    assert {"trim", "outcome", "complete_profile", "top_evidence", "country"} <= columns
    old = conn.execute("SELECT * FROM submissions").fetchone()
    assert old["outcome"] == "" and old["trim"] == ""  # not yet evaluated

    requirements = load_requirements(REQUIREMENTS)
    assert db.reevaluate_all(requirements) == 1

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    sub = conn.execute("SELECT * FROM submissions").fetchone()
    assert (sub["outcome"], sub["complete_profile"], sub["top_evidence"], sub["trim"], sub["verdict"]) == (
        "full_22", "2.2", "2.2", "Z", "ready"
    )
    assert sub["requirements_version"] == requirements.version
    readings = conn.execute("SELECT * FROM module_readings ORDER BY rowid").fetchall()
    assert len(readings) == 37
    bcm = next(r for r in readings if r["code"] == "BCM")
    assert (bcm["module_id"], bcm["extracted"], bcm["level"], bcm["status"]) == ("BCM", 42, "2.2", "ok")
    assert all(r["code"] for r in readings)  # code recovered from raw_name

    # Opening again is a no-op (idempotent migration), and the data survives
    Database(path)
    assert db.stats()["unique_vins"] == 1
    # upload_events was seeded from the existing rows, once
    conn = sqlite3.connect(path)
    assert tuple(conn.execute("SELECT COUNT(*), SUM(count) FROM upload_events").fetchone()) == (1, 1)


def test_reevaluation_applies_changed_requirements(tmp_path):
    db = Database(tmp_path / "m.sqlite3")
    requirements = load_requirements(REQUIREMENTS)
    report = parse_report((FIXTURES / "olp_report_22_full.txt").read_bytes(), "r.txt")
    db.store_submission(report, evaluate(report, requirements), "en", None)
    assert db.stats()["outcomes"] == {"full_22": 1}

    # Re-evaluating against the same requirements changes nothing (ECC 2.2 is 25, the car shows 25)
    stricter = REQUIREMENTS.read_text()
    assert 'levels: {"2.0": 19, "2.1": 24, "2.2": 25}' in stricter
    from app.rules import parse_requirements_text
    db.reevaluate_all(parse_requirements_text(stricter))
    assert db.stats()["outcomes"] == {"full_22": 1}
    # ...and to 26: now the car is a 2.2 zebra (ECC below 2.2, everything else on 2.2)
    db.reevaluate_all(parse_requirements_text(stricter.replace('"2.2": 25}', '"2.2": 26}')))
    assert db.stats()["outcomes"] == {"zebra_22": 1}


def test_delete_vehicle_removes_every_submission_and_names_the_files(tmp_path):
    db = Database(tmp_path / "m.sqlite3")
    requirements = load_requirements(REQUIREMENTS)
    for name, filename in [("olp_report_21_full.txt", "a.txt"), ("olp_report_21_full.txt", "b.txt"),
                           ("olp_report_22_full.txt", "c.txt")]:
        report = parse_report((FIXTURES / name).read_bytes(), name)
        db.store_submission(report, evaluate(report, requirements), "en", filename)
    assert db.stats()["total_submissions"] == 3

    vin_21 = parse_report((FIXTURES / "olp_report_21_full.txt").read_bytes(), "x").vin
    assert sorted(db.delete_vehicle(vin_21.lower())) == ["a.txt", "b.txt"]
    stats = db.stats()
    assert (stats["unique_vins"], stats["total_submissions"]) == (1, 1)
    conn = sqlite3.connect(db.path)
    assert conn.execute("SELECT COUNT(*) FROM module_readings").fetchone()[0] == 37
    assert conn.execute("SELECT COUNT(*) FROM upload_events").fetchone()[0] == 1  # the deleted car's events went too
    assert db.delete_vehicle("VCF1ZBE20PG000000") == []


def test_upload_events_keep_their_dates_through_dedup_and_merge(tmp_path):
    """The time series count upload events, not submission rows: an identical
    re-upload refreshes the row's timestamp but earlier uploads stay on the
    day they happened, and merging duplicates in the admin console keeps
    every event. Seeding an existing database counts each row's upload_count
    at the row's timestamp (older per-upload times are not known)."""
    from datetime import UTC, datetime, timedelta

    db = Database(tmp_path / "m.sqlite3")
    requirements = load_requirements(REQUIREMENTS)
    report = parse_report((FIXTURES / "olp_report_21_full.txt").read_bytes(), "x")
    evaluation = evaluate(report, requirements)
    ten_days_ago = (datetime.now(UTC) - timedelta(days=10)).isoformat()

    sid, _ = db.store_upload(report, evaluation, "en", "a.txt")
    with db._connect() as conn:  # the first upload happened ten days ago
        conn.execute("UPDATE submissions SET uploaded_at = ? WHERE id = ?", (ten_days_ago, sid))
        conn.execute("UPDATE upload_events SET uploaded_at = ? WHERE submission_id = ?", (ten_days_ago, sid))
    same, replaced = db.store_upload(report, evaluation, "en", "b.txt")
    assert same == sid and replaced == "a.txt"
    days = db.uploads_over_time()["day"]
    assert days[-11]["uploads"] == 1 and days[-1]["uploads"] == 1  # ten days ago and today, not 2 today
    assert sum(d["uploads"] for d in days) == 2 and db.stats()["total_submissions"] == 2

    # Two rows with the same report (from before dedup) merged in the admin
    # console: the earlier row's event follows the surviving row.
    other = db.store_submission(report, evaluation, "en", "c.txt")
    with db._connect() as conn:
        conn.execute("UPDATE submissions SET uploaded_at = ? WHERE id = ?", ((datetime.now(UTC) + timedelta(seconds=1)).isoformat(), other))
    assert db.merge_duplicate_submissions() == (1, ["b.txt"])
    with db._connect() as conn:
        events = conn.execute("SELECT submission_id, uploaded_at FROM upload_events ORDER BY uploaded_at").fetchall()
    assert [e["submission_id"] for e in events] == [other] * 3 and events[0]["uploaded_at"] == ten_days_ago
    assert sum(d["uploads"] for d in db.uploads_over_time()["day"]) == 3

    # A database from before the table: seeded once, then left alone
    with db._connect() as conn:
        conn.execute("DROP TABLE upload_events")
    seeded = Database(db.path)
    with seeded._connect() as conn:
        assert tuple(conn.execute("SELECT COUNT(*), SUM(count) FROM upload_events").fetchone()) == (1, 3)
    Database(db.path)
    with seeded._connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM upload_events").fetchone()[0] == 1


def test_older_report_is_detected_by_report_date():
    """An OLP export dated before the car's current report must not become
    the current one; without readable dates nothing can be said."""
    from app.parser import parse_report_date

    assert parse_report_date("2026-08-28 18:15:16.564271").year == 2026
    assert parse_report_date("") is None and parse_report_date("yesterday") is None
    assert parse_report_date("2026-08-28 18:15:16.564271").tzinfo is not None


def test_fleet_statistics_count_outcomes_levels_and_split_cars(tmp_path):
    db = Database(tmp_path / "m.sqlite3")
    requirements = load_requirements(REQUIREMENTS)

    def _store(name, vin_suffix, **overrides):
        report = parse_report((FIXTURES / name).read_bytes(), name)
        report.vin = report.vin[:-2] + vin_suffix
        for m in report.modules:
            if m.code in overrides:
                m.supplier_sw = overrides[m.code]
        db.store_submission(report, evaluate(report, requirements), "en", None, country="NO")

    _store("olp_report_21_full.txt", "01")
    _store("olp_report_22_full.txt", "02")
    _store("olp_report_21_full.txt", "03", BCM="BCM395042", VCU="VCU039023")   # 2.2 zebra
    _store("olp_report.txt", "04")                                           # BCM 21: 2.1 zebra
    _store("olp_report_marlin.txt", "05")
    _store("olp_report_21_full.txt", "01")                                   # re-upload, same car

    stats = db.stats(profiles=requirements.profiles, target=requirements.target_profile)
    assert (stats["unique_vins"], stats["total_submissions"]) == (5, 6)
    assert stats["outcomes"] == {"full_21": 1, "full_22": 1, "zebra_22": 1, "zebra_21": 1, "marlin": 1}
    assert stats["trims"] == [{"trim": "Z", "n": 5}]
    assert stats["countries"] == [{"country": "NO", "n": 5}]
    assert stats["per_week"][0]["uploads"] == 6 and stats["per_week"][0]["vehicles"] == 5
    # The 2.2 zebra is held back by ECC, ESP, IBS and both MCUs; the 2.1 zebra by BCM
    assert stats["split"]["zebra_22"]["cars"] == 1
    assert {m["module_id"] for m in stats["split"]["zebra_22"]["modules"]} == {"ECC", "ESP", "IBS", "MCU_F", "MCU_R"}
    assert stats["split"]["zebra_21"] == {"cars": 1, "modules": [{"module_id": "BCM", "n": 1}]}
    # BCM over the five cars: 21 (below every profile), 30, 42, 42, 42
    assert stats["module_levels"]["BCM"] == {"below": 1, "2.1": 1, "2.2": 3}
    assert stats["profiles"] == ["2.0", "2.1", "2.2"]
    # Every control unit, requirements or not, by ECU code over the latest reports
    assert stats["all_module_versions"]["GW"] == [{"version": "GW500002", "count": 5}]
    assert {v["version"] for v in stats["all_module_versions"]["BCM"]} == {"BCM395021", "BCM395030", "BCM395042"}


def test_time_series_and_fleet_movement(tmp_path):
    """Uploads per day/week/month are zero-filled and consistent, and vehicles
    with several uploads are classified by how they moved on the update ladder
    and which modules were lifted between the first and the latest report."""
    from datetime import UTC, datetime, timedelta

    db = Database(tmp_path / "m.sqlite3")
    requirements = load_requirements(REQUIREMENTS)

    def _store(name, vin_suffix, days_ago, **overrides):
        report = parse_report((FIXTURES / name).read_bytes(), name)
        report.vin = report.vin[:-2] + vin_suffix
        for m in report.modules:
            if m.code in overrides:
                m.supplier_sw = overrides[m.code]
        sid = db.store_submission(report, evaluate(report, requirements), "en", None)
        when = (datetime.now(UTC) - timedelta(days=days_ago)).isoformat()
        with db._connect() as conn:  # backdate: store_submission stamps "now"
            conn.execute("UPDATE submissions SET uploaded_at = ? WHERE id = ?", (when, sid))
            conn.execute("UPDATE upload_events SET uploaded_at = ? WHERE submission_id = ?", (when, sid))

    # Car 01: clean 2.1 (40 days ago) -> full 2.2 (2 days ago): BCM, ESP, IBS, MCUs, VCU lifted
    _store("olp_report_21_full.txt", "01", 40)
    _store("olp_report_22_full.txt", "01", 2)
    # Car 02: full 2.2 (10 days ago) -> Marlin (1 day ago): VCU 23 -> 24
    _store("olp_report_22_full.txt", "02", 10)
    _store("olp_report_marlin.txt", "02", 1)
    # Car 03: two identical uploads, nothing changed
    _store("olp_report_21_full.txt", "03", 5)
    _store("olp_report_21_full.txt", "03", 0)
    # Car 04: one upload only
    _store("olp_report.txt", "04", 3)

    ts = db.uploads_over_time()
    assert len(ts["day"]) == 60 and len(ts["week"]) == 26
    assert sum(p["uploads"] for p in ts["day"]) == 7  # all within 60 days
    assert sum(p["uploads"] for p in ts["week"]) == 7
    assert sum(p["uploads"] for p in ts["month"]) == 7
    assert ts["day"][-1]["uploads"] == 1 and ts["day"][-1]["vehicles"] == 1  # today: car 03
    assert ts["day"][-3]["uploads"] == 1  # two days ago: car 01
    assert ts["month"][-1]["period"] == datetime.now(UTC).strftime("%Y-%m")
    assert all(p["uploads"] >= p["vehicles"] for p in ts["day"] + ts["week"] + ts["month"])

    progress = db.fleet_progress()
    assert (progress["multi"], progress["improved"], progress["reached_marlin"]) == (3, 2, 1)
    by_vin = {v["vin"][-2:]: v for v in progress["vehicles"]}
    assert by_vin["01"]["direction"] == "up" and by_vin["01"]["first_outcome"] == "full_21"
    assert {(lift["module_id"], lift["from"], lift["to"]) for lift in by_vin["01"]["lifts"]} == {
        ("BCM", 30, 42), ("ESP", 402, 501), ("IBS", 400, 401), ("ECC", 24, 25),
        ("MCU_F", 19, 21), ("MCU_R", 19, 21), ("VCU", 21, 23),
    }
    assert by_vin["02"]["lifts"] == [{"module_id": "VCU", "from": 23, "to": 24}]
    assert by_vin["03"]["direction"] == "same" and by_vin["03"]["lifts"] == []
    assert progress["module_lifts"] == 8
    assert {(x["from"], x["to"], x["n"]) for x in progress["transitions"]} == {
        ("full_21", "full_22", 1), ("full_22", "marlin", 1), ("full_21", "full_21", 1),
    }
    assert progress["vehicles"][0]["vin"].endswith("03")  # newest last upload first

    history = db.fleet_status_by_month()
    assert history[-1]["total"] == 4
    assert history[-1]["counts"] == {"full_22": 1, "marlin": 1, "full_21": 1, "zebra_21": 1}
    assert history[0]["total"] >= 1  # the month of the oldest upload has at least car 01

    assert Database(tmp_path / "empty.sqlite3").fleet_status_by_month() == []
    assert Database(tmp_path / "empty.sqlite3").uploads_over_time()["month"] == []


def test_reevaluate_strips_cid_padding_from_old_rows(tmp_path):
    """Rows stored before the parser stripped (cid:0) padding are cleaned by
    'Re-evaluate all', so the stats stop showing 'BMSN39021(cid:0)' as a version."""
    path = tmp_path / "m.sqlite3"
    _old_database(path, "olp_report.txt", "VCF1ZBE20PG099999")
    conn = sqlite3.connect(path)
    conn.execute("UPDATE module_readings SET version = version || '(cid:0)' WHERE raw_name LIKE 'BMS - %'")
    conn.commit()
    conn.close()
    db = Database(path)
    db.reevaluate_all(load_requirements(REQUIREMENTS))
    conn = sqlite3.connect(path)
    versions = [r[0] for r in conn.execute("SELECT version FROM module_readings WHERE code = 'BMS'")]
    assert versions == ["BMSN39021"]


def test_reevaluate_reparses_stored_file(tmp_path):
    """When the stored report file still exists, 'Re-evaluate all' parses it
    again, so a parser fix (here: the older 'Supplier Software Version' label)
    reaches rows that were stored with empty versions."""
    path = tmp_path / "m.sqlite3"
    uploads = tmp_path / "uploads"
    uploads.mkdir()
    old_label = (FIXTURES / "olp_report.txt").read_text().replace("Supplier SW Version", "Supplier Software Version")
    (uploads / "stored.txt").write_text(old_label)
    _old_database(path, "olp_report.txt", "VCF1ZBE20PG099999")
    conn = sqlite3.connect(path)
    conn.execute("UPDATE submissions SET stored_filename = 'stored.txt'")
    conn.execute("UPDATE module_readings SET version = ''")  # what the old parser stored
    conn.commit()
    conn.close()
    db = Database(path)
    db.reevaluate_all(load_requirements(REQUIREMENTS), uploads)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    bcm = conn.execute("SELECT version, extracted, status FROM module_readings WHERE code = 'BCM'").fetchone()
    assert (bcm["version"], bcm["extracted"], bcm["status"]) == ("BCM395021", 21, "outdated")
    assert conn.execute("SELECT outcome FROM submissions").fetchone()[0] == "zebra_21"


def test_database_file_is_renamed_on_startup(tmp_path):
    """Project rename: marlin.sqlite3 (with WAL side files) moves to
    oceansoftwarecheck.sqlite3 the first time the app starts; a second call
    is a no-op, and an existing new file is never overwritten."""
    from app.db import DB_FILENAME, migrate_database_name

    old = tmp_path / "marlin.sqlite3"
    _old_database(old, "olp_report.txt", "VCF1ZBE20PG099999")
    (tmp_path / "marlin.sqlite3-wal").write_bytes(b"")
    assert migrate_database_name(tmp_path) is True
    assert not old.exists() and (tmp_path / DB_FILENAME).exists() and (tmp_path / (DB_FILENAME + "-wal")).exists()
    assert migrate_database_name(tmp_path) is False
    conn = sqlite3.connect(tmp_path / DB_FILENAME)
    assert conn.execute("SELECT COUNT(*) FROM submissions").fetchone()[0] == 1
    old.write_bytes(b"stale")  # an old file reappearing must not clobber the live one
    assert migrate_database_name(tmp_path) is False and (tmp_path / DB_FILENAME).stat().st_size > 5


def test_env_prefers_osc_and_falls_back_to_marlin(monkeypatch):
    from app.config import env

    monkeypatch.delenv("OSC_THING", raising=False)
    monkeypatch.setenv("MARLIN_THING", "old")
    assert env("THING", "d") == "old"
    monkeypatch.setenv("OSC_THING", "new")
    assert env("THING", "d") == "new"
    monkeypatch.delenv("OSC_THING")
    monkeypatch.delenv("MARLIN_THING")
    assert env("THING", "d") == "d"
