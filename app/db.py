"""SQLite storage: the association's vehicle register (every analyzed report,
with all module readings), usage statistics, audit log and admin sessions.

Storage is mandatory since v2 (Sep 2026): a member must accept it to run the
analysis. Earlier rows come from the consent period and are kept.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import ClassVar

from .parser import MIN_MODULES, ModuleReading, ParsedReport, parse_report_date
from .rules import OUTCOME_MARLIN, Evaluation, RequirementSet, evaluate

SCHEMA = """
CREATE TABLE IF NOT EXISTS submissions (
    id TEXT PRIMARY KEY,
    vin TEXT NOT NULL,
    vin_hash TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
    verdict TEXT NOT NULL,
    requirements_version TEXT NOT NULL,
    lang TEXT NOT NULL DEFAULT 'en',
    stored_filename TEXT,
    trim TEXT NOT NULL DEFAULT '',
    outcome TEXT NOT NULL DEFAULT '',
    complete_profile TEXT,
    top_evidence TEXT,
    report_date TEXT NOT NULL DEFAULT '',
    country TEXT NOT NULL DEFAULT '',
    upload_count INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_submissions_vin_hash ON submissions(vin_hash);

-- One row per upload event, written whether the upload became a new
-- submission or refreshed an identical one. The time series read this table,
-- so a refreshed row moving its uploaded_at never moves earlier uploads.
-- Seeded once from submissions (one event per row, count = upload_count)
-- for databases from before the table existed.
CREATE TABLE IF NOT EXISTS upload_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id TEXT,
    vin_hash TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_upload_events_at ON upload_events(uploaded_at);

-- One row per ECU block in the report. module_id/status/extracted/level/
-- evidence_level are the rule engine's view and are rewritten on
-- re-evaluation; code/section and the four version fields are the report's.
CREATE TABLE IF NOT EXISTS module_readings (
    submission_id TEXT NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
    module_id TEXT,
    raw_name TEXT NOT NULL,
    version TEXT NOT NULL,
    status TEXT NOT NULL,
    code TEXT NOT NULL DEFAULT '',
    section TEXT NOT NULL DEFAULT '',
    extracted INTEGER,
    level TEXT,
    evidence_level TEXT,
    software TEXT NOT NULL DEFAULT '',
    hardware TEXT NOT NULL DEFAULT '',
    bootloader TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_readings_module ON module_readings(module_id);
CREATE INDEX IF NOT EXISTS idx_readings_submission ON module_readings(submission_id);

-- Permanent per-vehicle link: an unguessable key that always shows the
-- vehicle's latest report. Created on the first upload of a VIN, reused
-- afterwards, removed with the vehicle.
CREATE TABLE IF NOT EXISTS vehicle_links (
    vin_hash TEXT PRIMARY KEY,
    vin TEXT NOT NULL,
    link_key TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

-- Anonymous usage statistics: never VIN, report content, or raw IP.
-- ip_hash is a daily-rotating hash, only used to count unique users per day.
CREATE TABLE IF NOT EXISTS usage_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    day TEXT NOT NULL,
    country TEXT NOT NULL DEFAULT '',
    ui_lang TEXT NOT NULL DEFAULT '',
    browser_lang TEXT NOT NULL DEFAULT '',
    outcome TEXT NOT NULL,
    consent INTEGER NOT NULL DEFAULT 0,
    ip_hash TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_usage_day ON usage_events(day);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    username TEXT NOT NULL,
    ip TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT NOT NULL
);

-- Admin login sessions (form login). Only a hash of the cookie token is
-- stored, so a copy of the database does not yield usable sessions.
CREATE TABLE IF NOT EXISTS admin_sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_seen_at REAL NOT NULL
);

-- Admin users: password hash (PBKDF2, see auth.py), role, and the TOTP
-- secret once MFA is set up. Bootstrapped from admin_users.yaml when empty.
CREATE TABLE IF NOT EXISTS admin_users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    totp_secret TEXT,
    totp_confirmed_at TEXT,
    totp_last_counter INTEGER,
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    password_changed_at TEXT,
    last_login_at TEXT
);

-- Feature switches and other settings the admin console controls.
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL DEFAULT ''
);

-- Passkeys (WebAuthn, app/passkeys.py): second factor or passwordless sign-in.
CREATE TABLE IF NOT EXISTS admin_passkeys (
    credential_id TEXT PRIMARY KEY,
    username TEXT NOT NULL REFERENCES admin_users(username) ON DELETE CASCADE,
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    name TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
"""

# Columns added after the first release, applied to existing databases with
# ALTER TABLE (SQLite cannot add columns through CREATE TABLE IF NOT EXISTS).
_MIGRATIONS = {
    "submissions": [
        ("upload_count", "INTEGER NOT NULL DEFAULT 1"),
        ("trim", "TEXT NOT NULL DEFAULT ''"),
        ("outcome", "TEXT NOT NULL DEFAULT ''"),
        ("complete_profile", "TEXT"),
        ("top_evidence", "TEXT"),
        ("report_date", "TEXT NOT NULL DEFAULT ''"),
        ("country", "TEXT NOT NULL DEFAULT ''"),
        ("marlin_missing", "TEXT"),  # Marlin cars: package modules below the Marlin level, comma-separated ("" = complete); NULL otherwise
    ],
    "admin_users": [
        ("last_login_at", "TEXT"),
    ],
    "admin_sessions": [
        ("mfa_pending", "INTEGER NOT NULL DEFAULT 0"),
        ("mfa_setup_required", "INTEGER NOT NULL DEFAULT 0"),
        ("webauthn_challenge", "TEXT"),
    ],
    "module_readings": [
        ("code", "TEXT NOT NULL DEFAULT ''"),
        ("section", "TEXT NOT NULL DEFAULT ''"),
        ("extracted", "INTEGER"),
        ("level", "TEXT"),
        ("evidence_level", "TEXT"),
        ("software", "TEXT NOT NULL DEFAULT ''"),
        ("hardware", "TEXT NOT NULL DEFAULT ''"),
        ("bootloader", "TEXT NOT NULL DEFAULT ''"),
    ],
}


# The update ladder: where a car sits on the road to Marlin. Used to say
# whether a vehicle moved up between its first and latest upload.
OUTCOME_RANK = {"zebra_21": 0, "full_21": 1, "zebra_22": 2, "full_22": 3, "marlin": 4}


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def vin_hash(vin: str) -> str:
    return hashlib.sha256(vin.upper().encode()).hexdigest()


_INSERT_READING = (
    "INSERT INTO module_readings (submission_id, module_id, raw_name, version, status,"
    " code, section, extracted, level, evidence_level, software, hardware, bootloader)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


def _marlin_missing(evaluation: Evaluation) -> str | None:
    """For a car on Marlin: the package modules below the Marlin level, as a
    comma-separated string ("" when the package is complete). None for cars
    not on Marlin or when the requirements define no Marlin package."""
    if evaluation.outcome != OUTCOME_MARLIN or not evaluation.marlin_results:
        return None
    return ",".join(r.requirement.id for r in evaluation.marlin_below)


def _reading_rows(submission_id: str, evaluation: Evaluation) -> list[tuple]:
    """One row per ECU block: the evaluated modules (with the rule engine's
    view) followed by the report's other modules (status "extra")."""
    rows = []
    for r in evaluation.results:
        m = r.reading
        if m is None:
            continue
        rows.append((
            submission_id, r.requirement.id, m.raw_name, m.supplier_sw, r.status,
            m.code, m.section, r.extracted, r.level, r.evidence_level,
            m.software, m.hardware, m.bootloader,
        ))
    for m in evaluation.extra_modules:
        rows.append((
            submission_id, None, m.raw_name, m.supplier_sw, "extra",
            m.code, m.section, None, None, None, m.software, m.hardware, m.bootloader,
        ))
    return rows


def _report_signature(report: ParsedReport) -> tuple:
    """What makes two uploads 'the same report': every control unit with all
    four version fields. Order-independent; the report date is ignored."""
    return tuple(sorted(
        (m.code, m.supplier_sw, m.software, m.hardware, m.bootloader) for m in report.modules
    ))


def _rows_signature(rows) -> tuple:
    return tuple(sorted(
        ((row["code"] or row["raw_name"].split(" - ", 1)[0]), row["version"], row["software"] or "",
         row["hardware"] or "", row["bootloader"] or "")
        for row in rows
    ))


def _report_from_rows(vin: str, rows, report_date: str = "") -> ParsedReport:
    """Rebuilds a ParsedReport from stored readings. Rows from before v2 have
    no `code`; it is recovered from raw_name ("CODE - Name")."""
    from .parser import clean_value  # rows stored before the (cid:0) fix carry padding glyphs

    modules = []
    for row in rows:
        code = row["code"] or row["raw_name"].split(" - ", 1)[0]
        name = row["raw_name"].split(" - ", 1)[1] if " - " in row["raw_name"] else row["raw_name"]
        modules.append(ModuleReading(
            code=code, name=name, section=row["section"] or "", supplier_sw=clean_value(row["version"] or ""),
            software=clean_value(row["software"] or ""), hardware=clean_value(row["hardware"] or ""),
            bootloader=clean_value(row["bootloader"] or ""),
        ))
    meta = {"report_date": report_date} if report_date else {}
    return ParsedReport(vin=vin, modules=modules, meta=meta)


DB_FILENAME = "oceansoftwarecheck.sqlite3"
_OLD_DB_FILENAME = "marlin.sqlite3"


def migrate_database_name(data_dir: Path) -> bool:
    """Project rename 2026-09-16: moves marlin.sqlite3 (and its WAL/SHM
    side files) to oceansoftwarecheck.sqlite3 when the new file does not
    exist yet. Returns True when something was moved."""
    new, old = data_dir / DB_FILENAME, data_dir / _OLD_DB_FILENAME
    if new.exists() or not old.exists():
        return False
    for suffix in ("", "-wal", "-shm"):
        src = Path(str(old) + suffix)
        if src.exists():
            os.replace(src, Path(str(new) + suffix))
    return True


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")  # persistent; set once per database file
            conn.executescript(SCHEMA)
            self._migrate(conn)

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        for table, columns in _MIGRATIONS.items():
            existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
            for name, definition in columns:
                if name not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
        # upload_events: seeded from the submissions that exist when the table
        # is first created. Earlier uploads folded into a row by deduplication
        # had lost their own timestamps already; they are counted at the
        # row's timestamp, which is all that is known about them.
        if (conn.execute("SELECT COUNT(*) AS n FROM upload_events").fetchone()["n"] == 0
                and conn.execute("SELECT COUNT(*) AS n FROM submissions").fetchone()["n"] > 0):
            conn.execute(
                "INSERT INTO upload_events (submission_id, vin_hash, uploaded_at, count)"
                " SELECT id, vin_hash, uploaded_at, upload_count FROM submissions"
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """One connection per unit of work: commits on success, rolls back on
        error, and always closes (sqlite3's own context manager only commits)."""
        conn = sqlite3.connect(self.path, timeout=10)
        try:
            conn.execute("PRAGMA foreign_keys=ON")
            conn.row_factory = sqlite3.Row
            with conn:
                yield conn
        finally:
            conn.close()

    def store_submission(
        self,
        report: ParsedReport,
        evaluation: Evaluation,
        lang: str,
        stored_filename: str | None,
        country: str = "",
    ) -> str:
        submission_id = uuid.uuid4().hex
        uploaded_at = datetime.now(UTC).isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO submissions (id, vin, vin_hash, uploaded_at, verdict,"
                " requirements_version, lang, stored_filename, trim, outcome,"
                " complete_profile, top_evidence, report_date, country, marlin_missing)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    submission_id,
                    report.vin.upper(),
                    vin_hash(report.vin),
                    uploaded_at,
                    evaluation.verdict,
                    evaluation.requirements_version,
                    lang,
                    stored_filename,
                    evaluation.trim,
                    evaluation.outcome,
                    evaluation.complete_profile,
                    evaluation.top_evidence,
                    str(report.meta.get("report_date", ""))[:32],
                    country[:8],
                    _marlin_missing(evaluation),
                ),
            )
            conn.executemany(_INSERT_READING, _reading_rows(submission_id, evaluation))
            conn.execute(
                "INSERT INTO upload_events (submission_id, vin_hash, uploaded_at) VALUES (?, ?, ?)",
                (submission_id, vin_hash(report.vin), uploaded_at),
            )
        return submission_id

    # --- time series and fleet movement ---------------------------------------

    def uploads_over_time(self) -> dict[str, list[dict]]:
        """Uploads and unique vehicles per day (last 60 days), per week (last
        26 weeks, Monday-based like SQLite's %W) and per month (since the first
        upload), oldest first and zero-filled so the axis is continuous."""
        today = datetime.now(UTC).date()

        def series(fmt: str, periods: list[str]) -> list[dict]:
            with self._connect() as conn:
                counted = {
                    row["period"]: (row["uploads"], row["vehicles"])
                    for row in conn.execute(
                        f"SELECT strftime('{fmt}', uploaded_at) AS period, SUM(count) AS uploads,"
                        " COUNT(DISTINCT vin_hash) AS vehicles FROM upload_events GROUP BY period"
                    )
                }
            return [
                {"period": key, "uploads": counted.get(key, (0, 0))[0], "vehicles": counted.get(key, (0, 0))[1]}
                for key in periods
            ]

        days = [(today - timedelta(days=i)).isoformat() for i in range(59, -1, -1)]
        weeks = []
        for i in range(25, -1, -1):
            key = (today - timedelta(days=7 * i)).strftime("%Y-W%W")
            if key not in weeks:
                weeks.append(key)
        with self._connect() as conn:
            first = conn.execute("SELECT MIN(uploaded_at) AS f FROM upload_events").fetchone()["f"]
        months: list[str] = []
        if first:
            y, m = int(first[:4]), int(first[5:7])
            while (y, m) <= (today.year, today.month):
                months.append(f"{y:04d}-{m:02d}")
                y, m = (y + 1, 1) if m == 12 else (y, m + 1)
        return {
            "day": series("%Y-%m-%d", days),
            "week": series("%Y-W%W", weeks),
            "month": series("%Y-%m", months),
        }

    def fleet_progress(self) -> dict:
        """How vehicles with more than one upload have moved: first vs latest
        outcome on the update ladder, and which required modules were lifted
        (extracted number higher in the latest than in the first report).
        `vehicles` carries VINs and is for the admin register only; the other
        keys are aggregates safe for the public dashboard."""
        with self._connect() as conn:
            subs = conn.execute(
                "SELECT id, vin, vin_hash, uploaded_at, outcome, upload_count FROM submissions"
                " ORDER BY vin_hash, uploaded_at"
            ).fetchall()
            by_vin: dict[str, list] = {}
            for row in subs:
                by_vin.setdefault(row["vin_hash"], []).append(row)

            def readings(submission_id: str) -> dict[str, int]:
                return {
                    row["module_id"]: row["extracted"]
                    for row in conn.execute(
                        "SELECT module_id, extracted FROM module_readings"
                        " WHERE submission_id = ? AND module_id IS NOT NULL",
                        (submission_id,),
                    )
                    if row["extracted"] is not None
                }

            vehicles = []
            for rows in by_vin.values():
                if len(rows) < 2:
                    continue
                first, last = rows[0], rows[-1]
                before, after = readings(first["id"]), readings(last["id"])
                lifts = [
                    {"module_id": m, "from": before[m], "to": after[m]}
                    for m in sorted(after)
                    if m in before and after[m] > before[m]
                ]
                rank_first = OUTCOME_RANK.get(first["outcome"], -1)
                rank_last = OUTCOME_RANK.get(last["outcome"], -1)
                vehicles.append({
                    "vin": last["vin"],
                    "uploads": sum(r["upload_count"] for r in rows),
                    "first_at": first["uploaded_at"], "first_outcome": first["outcome"],
                    "last_at": last["uploaded_at"], "last_outcome": last["outcome"],
                    "lifts": lifts,
                    "direction": "up" if rank_last > rank_first else ("down" if rank_last < rank_first else "same"),
                })
        vehicles.sort(key=lambda v: v["last_at"], reverse=True)
        transitions: dict[tuple[str, str], int] = {}
        for v in vehicles:
            key = (v["first_outcome"], v["last_outcome"])
            transitions[key] = transitions.get(key, 0) + 1
        return {
            "multi": len(vehicles),
            "improved": sum(1 for v in vehicles if v["direction"] == "up"),
            "reached_marlin": sum(
                1 for v in vehicles if v["last_outcome"] == "marlin" and v["first_outcome"] != "marlin"
            ),
            "module_lifts": sum(len(v["lifts"]) for v in vehicles),
            "transitions": [
                {"from": a, "to": b, "n": n}
                for (a, b), n in sorted(transitions.items(), key=lambda kv: (-kv[1], kv[0]))
            ],
            "vehicles": vehicles,
        }

    def fleet_status_by_month(self) -> list[dict]:
        """For every month since the first upload: each vehicle's latest known
        outcome at the end of that month, counted per outcome. Outcomes are the
        current requirements' view of each stored report (re-evaluation
        rewrites them), so the series shows real software status over time."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT vin_hash, uploaded_at, outcome FROM submissions ORDER BY uploaded_at"
            ).fetchall()
        if not rows:
            return []
        today = datetime.now(UTC).date()
        y, m = int(rows[0]["uploaded_at"][:4]), int(rows[0]["uploaded_at"][5:7])
        months = []
        while (y, m) <= (today.year, today.month):
            months.append(f"{y:04d}-{m:02d}")
            y, m = (y + 1, 1) if m == 12 else (y, m + 1)
        state: dict[str, str] = {}
        i = 0
        out = []
        for month in months:
            while i < len(rows) and rows[i]["uploaded_at"][:7] <= month:
                state[rows[i]["vin_hash"]] = rows[i]["outcome"]
                i += 1
            counts: dict[str, int] = {}
            for outcome in state.values():
                counts[outcome] = counts.get(outcome, 0) + 1
            out.append({"month": month, "counts": counts, "total": len(state)})
        return out

    # --- permanent per-vehicle links -----------------------------------------

    def link_key_for(self, vin: str) -> str:
        """The vehicle's permanent link key, created on first use."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT link_key FROM vehicle_links WHERE vin_hash = ?", (vin_hash(vin),)
            ).fetchone()
            if row:
                return row["link_key"]
            key = secrets.token_urlsafe(16)
            conn.execute(
                "INSERT INTO vehicle_links (vin_hash, vin, link_key, created_at) VALUES (?, ?, ?, ?)",
                (vin_hash(vin), vin.upper(), key, datetime.now(UTC).isoformat()),
            )
            return key

    def latest_report_by_key(self, key: str) -> tuple[ParsedReport, dict] | None:
        """The latest stored report for the vehicle behind a link key, rebuilt
        from its readings, plus the submission row. None for unknown keys or a
        vehicle whose submissions were deleted."""
        with self._connect() as conn:
            link = conn.execute(
                "SELECT vin, vin_hash FROM vehicle_links WHERE link_key = ?", (key,)
            ).fetchone()
            if not link:
                return None
            sub = conn.execute(
                "SELECT * FROM submissions WHERE vin_hash = ? ORDER BY uploaded_at DESC LIMIT 1",
                (link["vin_hash"],),
            ).fetchone()
            if not sub:
                return None
            rows = conn.execute(
                "SELECT raw_name, version, code, section, software, hardware, bootloader"
                " FROM module_readings WHERE submission_id = ? ORDER BY rowid",
                (sub["id"],),
            ).fetchall()
        return _report_from_rows(sub["vin"], rows, sub["report_date"]), dict(sub)

    def store_upload(self, report: ParsedReport, evaluation: Evaluation, lang: str,
                     stored_filename: str | None, country: str = "") -> tuple[str, str | None]:
        """Stores an upload, unless it is identical to the vehicle's latest
        report: then that row is refreshed instead (new timestamp, report
        date, file, language and country; upload_count + 1; outcome re-stored
        in case the requirements changed). Returns (submission id, replaced file name or
        None); the caller removes the replaced file."""
        with self._connect() as conn:
            latest = conn.execute(
                "SELECT id, stored_filename FROM submissions WHERE vin_hash = ? ORDER BY uploaded_at DESC LIMIT 1",
                (vin_hash(report.vin),),
            ).fetchone()
            if latest is not None:
                rows = conn.execute(
                    "SELECT raw_name, version, code, software, hardware, bootloader"
                    " FROM module_readings WHERE submission_id = ?", (latest["id"],)
                ).fetchall()
                if _rows_signature(rows) == _report_signature(report):
                    conn.execute(
                        "UPDATE submissions SET uploaded_at = ?, report_date = ?, lang = ?, stored_filename = ?,"
                        " country = ?, upload_count = upload_count + 1, verdict = ?, requirements_version = ?,"
                        " trim = ?, outcome = ?, complete_profile = ?, top_evidence = ?, marlin_missing = ?"
                        " WHERE id = ?",
                        (datetime.now(UTC).isoformat(), str(report.meta.get("report_date", ""))[:32], lang,
                         stored_filename, country[:8], evaluation.verdict, evaluation.requirements_version, evaluation.trim,
                         evaluation.outcome, evaluation.complete_profile, evaluation.top_evidence,
                         _marlin_missing(evaluation), latest["id"]),
                    )
                    conn.execute("DELETE FROM module_readings WHERE submission_id = ?", (latest["id"],))
                    conn.executemany(_INSERT_READING, _reading_rows(latest["id"], evaluation))
                    conn.execute(
                        "INSERT INTO upload_events (submission_id, vin_hash, uploaded_at) VALUES (?, ?, ?)",
                        (latest["id"], vin_hash(report.vin), datetime.now(UTC).isoformat()),
                    )
                    return latest["id"], latest["stored_filename"]
        return self.store_submission(report, evaluation, lang, stored_filename, country=country), None

    def newer_report_date(self, vin: str, report_date: str) -> str | None:
        """The vehicle's latest stored report date when it is later than
        `report_date`: an older OLP export uploaded by mistake must not become
        the car's current report. None when either date is missing or
        unreadable, or the new report is as new or newer."""
        new = parse_report_date(report_date)
        if new is None:
            return None
        with self._connect() as conn:
            latest = conn.execute(
                "SELECT report_date FROM submissions WHERE vin_hash = ? ORDER BY uploaded_at DESC LIMIT 1",
                (vin_hash(vin),),
            ).fetchone()
        stored = parse_report_date(latest["report_date"]) if latest else None
        return latest["report_date"] if stored and stored > new else None

    def merge_duplicate_submissions(self) -> tuple[int, list[str]]:
        """One-off clean-up: for every vehicle, consecutive uploads with the
        same report are merged into the latest of them (upload counts added
        up). Returns (rows removed, their stored file names)."""
        removed, files = 0, []
        with self._connect() as conn:
            subs = conn.execute(
                "SELECT id, vin_hash, uploaded_at, stored_filename, upload_count FROM submissions"
                " ORDER BY vin_hash, uploaded_at"
            ).fetchall()
            previous = None  # (vin_hash, signature, id)
            for sub in subs:
                rows = conn.execute(
                    "SELECT raw_name, version, code, software, hardware, bootloader"
                    " FROM module_readings WHERE submission_id = ?", (sub["id"],)
                ).fetchall()
                signature = _rows_signature(rows)
                if previous and previous[0] == sub["vin_hash"] and previous[1] == signature:
                    # same report as the one before it: fold the earlier row into this one
                    earlier = conn.execute("SELECT stored_filename, upload_count FROM submissions WHERE id = ?",
                                           (previous[2],)).fetchone()
                    conn.execute("UPDATE submissions SET upload_count = upload_count + ? WHERE id = ?",
                                 (earlier["upload_count"], sub["id"]))
                    conn.execute("UPDATE upload_events SET submission_id = ? WHERE submission_id = ?",
                                 (sub["id"], previous[2]))
                    conn.execute("DELETE FROM submissions WHERE id = ?", (previous[2],))
                    removed += 1
                    if earlier["stored_filename"]:
                        files.append(earlier["stored_filename"])
                previous = (sub["vin_hash"], signature, sub["id"])
        return removed, files

    # --- the vehicle register (admin) ----------------------------------------

    _LATEST = (
        "SELECT s.* FROM submissions s"
        " JOIN (SELECT vin_hash, MAX(uploaded_at) AS latest"
        "       FROM submissions GROUP BY vin_hash) m"
        " ON s.vin_hash = m.vin_hash AND s.uploaded_at = m.latest"
    )

    MIN_READINGS = MIN_MODULES  # rows from before the completeness check may still have fewer

    def fleet_vehicles(self, *, outcome: str = "", trim: str = "", query: str = "",
                       anomalies: bool = False, marlin_gap: str = "") -> list[dict]:
        """One row per VIN (latest submission), with the evaluated modules as
        {module_id: {"extracted", "level", "status", "version"}}. Filters are
        exact on outcome/trim and a substring on the VIN. `marlin_gap` = the
        top profile: only Marlin cars not fully at that profile or with an
        incomplete Marlin package."""
        filters = [
            ("outcome = ?", outcome),
            ("trim = ?", trim.upper()),
            ("vin LIKE ?", f"%{query.upper()}%" if query else ""),
            ("(outcome = 'marlin' AND (COALESCE(complete_profile, '') != ? OR COALESCE(marlin_missing, '') != ''))", marlin_gap),
        ]
        where = [sql for sql, value in filters if value]
        params = [value for _sql, value in filters if value]
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        with self._connect() as conn:
            vehicles = [
                dict(row) for row in conn.execute(
                    f"SELECT * FROM ({self._LATEST}){clause} ORDER BY uploaded_at DESC", params
                )
            ]
            by_id = {v["id"]: v for v in vehicles}
            for v in vehicles:
                v["modules"] = {}
                v["uploads"] = 0
                v["anomalies"] = []   # required modules missing, unreadable or empty
                v["readings"] = 0     # control units in the report
            if by_id:
                placeholders = ",".join("?" * len(by_id))
                for row in conn.execute(
                    "SELECT submission_id, module_id, extracted, level, status, version"
                    f" FROM module_readings WHERE module_id IS NOT NULL AND submission_id IN ({placeholders})",
                    list(by_id),
                ):
                    by_id[row["submission_id"]]["modules"][row["module_id"]] = {
                        "extracted": row["extracted"], "level": row["level"],
                        "status": row["status"], "version": row["version"],
                    }
                    if row["status"] in ("missing", "unparseable", "empty"):
                        by_id[row["submission_id"]]["anomalies"].append(row["module_id"])
                for row in conn.execute(
                    f"SELECT submission_id, COUNT(*) AS n FROM module_readings WHERE submission_id IN ({placeholders})"
                    " GROUP BY submission_id", list(by_id),
                ):
                    by_id[row["submission_id"]]["readings"] = row["n"]
                for row in conn.execute(
                    "SELECT vin_hash, SUM(upload_count) AS n FROM submissions GROUP BY vin_hash"
                ):
                    for v in vehicles:
                        if v["vin_hash"] == row["vin_hash"]:
                            v["uploads"] = row["n"]
        for v in vehicles:
            v["odd"] = bool(v["anomalies"]) or v["readings"] < self.MIN_READINGS
        if anomalies:
            vehicles = [v for v in vehicles if v["odd"]]
        return vehicles

    def changes_since_previous(self, vin: str, submission_id: str) -> dict | None:
        """What changed between the submission before `submission_id` and that
        submission, for the same VIN: outcome and every module whose Supplier
        SW Version differs (by ECU code, required or not). None when there is
        no earlier upload."""
        with self._connect() as conn:
            current = conn.execute("SELECT uploaded_at, outcome FROM submissions WHERE id = ?", (submission_id,)).fetchone()
            if current is None:
                return None
            previous = conn.execute(
                "SELECT id, uploaded_at, outcome FROM submissions WHERE vin_hash = ? AND uploaded_at < ?"
                " ORDER BY uploaded_at DESC LIMIT 1",
                (vin_hash(vin), current["uploaded_at"]),
            ).fetchone()
            if previous is None:
                return None

            def versions(sid: str) -> dict[str, str]:
                out: dict[str, str] = {}
                for row in conn.execute(
                    "SELECT raw_name, code, version FROM module_readings WHERE submission_id = ? ORDER BY rowid", (sid,)
                ):
                    code = row["code"] or row["raw_name"].split(" - ", 1)[0]
                    out.setdefault(code, row["version"])
                return out

            before, after = versions(previous["id"]), versions(submission_id)
        modules = [
            {"code": code, "before": before.get(code, ""), "after": after.get(code, "")}
            for code in sorted(set(before) | set(after))
            if before.get(code, "") != after.get(code, "")
        ]
        return {
            "previous_at": previous["uploaded_at"],
            "outcome_before": previous["outcome"], "outcome_after": current["outcome"],
            "modules": modules,
        }

    def vehicle_history(self, vin: str) -> list[dict]:
        """Every submission for the VIN, newest first, each with its readings."""
        with self._connect() as conn:
            subs = [
                dict(row) for row in conn.execute(
                    "SELECT * FROM submissions WHERE vin_hash = ? ORDER BY uploaded_at DESC",
                    (vin_hash(vin),),
                )
            ]
            for sub in subs:
                sub["readings"] = [
                    dict(row) for row in conn.execute(
                        "SELECT * FROM module_readings WHERE submission_id = ? ORDER BY rowid",
                        (sub["id"],),
                    )
                ]
        return subs

    def export_readings(self):
        """Every reading of every submission, joined with its submission —
        one row per ECU per upload, for the CSV export."""
        with self._connect() as conn:
            yield from (
                dict(row) for row in conn.execute(
                    "SELECT s.id AS submission_id, s.vin, s.uploaded_at, s.report_date, s.trim,"
                    " s.outcome, s.complete_profile, s.top_evidence, s.requirements_version, s.country,"
                    " mr.code, mr.raw_name, mr.section, mr.module_id, mr.version AS supplier_sw,"
                    " mr.software, mr.hardware, mr.bootloader, mr.extracted, mr.level,"
                    " mr.evidence_level, mr.status"
                    " FROM module_readings mr JOIN submissions s ON s.id = mr.submission_id"
                    " ORDER BY s.uploaded_at DESC, mr.rowid"
                )
            )

    # --- re-evaluation and deletion (vehicle register maintenance) ---------

    def reevaluate_all(self, requirements: RequirementSet, uploads_dir: Path | None = None) -> int:
        """Re-runs the rule engine on every stored report and rewrites the
        derived columns. The report is parsed again from the stored file when
        it still exists (so parser fixes reach old rows), otherwise rebuilt
        from its module readings. Backfills rows from before v2 and applies
        changed requirements. All-or-nothing."""
        from .parser import ReportParseError, parse_report

        count = 0
        with self._connect() as conn:
            submissions = conn.execute("SELECT id, vin, stored_filename, report_date FROM submissions").fetchall()
            for sub in submissions:
                report = None
                path = uploads_dir / Path(sub["stored_filename"]).name if uploads_dir and sub["stored_filename"] else None
                if path is not None and path.is_file():
                    try:
                        report = parse_report(path.read_bytes(), path.name)
                    except ReportParseError:
                        report = None
                if report is None or report.vin != sub["vin"]:
                    rows = conn.execute(
                        "SELECT raw_name, version, code, section, software, hardware, bootloader"
                        " FROM module_readings WHERE submission_id = ? ORDER BY rowid",
                        (sub["id"],),
                    ).fetchall()
                    report = _report_from_rows(sub["vin"], rows, sub["report_date"])
                evaluation = evaluate(report, requirements)
                conn.execute(
                    "UPDATE submissions SET verdict = ?, requirements_version = ?, trim = ?,"
                    " outcome = ?, complete_profile = ?, top_evidence = ?, marlin_missing = ? WHERE id = ?",
                    (evaluation.verdict, evaluation.requirements_version, evaluation.trim,
                     evaluation.outcome, evaluation.complete_profile, evaluation.top_evidence,
                     _marlin_missing(evaluation), sub["id"]),
                )
                conn.execute("DELETE FROM module_readings WHERE submission_id = ?", (sub["id"],))
                conn.executemany(_INSERT_READING, _reading_rows(sub["id"], evaluation))
                count += 1
        return count

    def delete_vehicle(self, vin: str) -> list[str]:
        """Deletes every submission for the VIN; returns the stored filenames
        so the caller can remove the files too."""
        with self._connect() as conn:
            files = [
                row["stored_filename"]
                for row in conn.execute(
                    "SELECT stored_filename FROM submissions WHERE vin_hash = ?", (vin_hash(vin),)
                )
                if row["stored_filename"]
            ]
            conn.execute("DELETE FROM submissions WHERE vin_hash = ?", (vin_hash(vin),))
            conn.execute("DELETE FROM upload_events WHERE vin_hash = ?", (vin_hash(vin),))
            conn.execute("DELETE FROM vehicle_links WHERE vin_hash = ?", (vin_hash(vin),))
        return files

    def add_usage(self, *, country: str, ui_lang: str, browser_lang: str,
                  outcome: str, consent: bool, ip_hash: str) -> None:
        now = datetime.now(UTC)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO usage_events (ts, day, country, ui_lang, browser_lang,"
                " outcome, consent, ip_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (now.isoformat(), now.strftime("%Y-%m-%d"), country, ui_lang,
                 browser_lang, outcome, int(consent), ip_hash),
            )

    def usage_stats(self, days: int = 14) -> dict:
        with self._connect() as conn:
            totals = conn.execute(
                "SELECT COUNT(*) AS n, SUM(consent) AS consented FROM usage_events"
            ).fetchone()
            outcomes = {
                row["outcome"]: row["n"]
                for row in conn.execute(
                    "SELECT outcome, COUNT(*) AS n FROM usage_events GROUP BY outcome"
                )
            }
            countries = [
                dict(row)
                for row in conn.execute(
                    "SELECT country, COUNT(*) AS n FROM usage_events"
                    " GROUP BY country ORDER BY n DESC LIMIT 15"
                )
            ]
            languages = [
                dict(row)
                for row in conn.execute(
                    "SELECT ui_lang, COUNT(*) AS n FROM usage_events"
                    " GROUP BY ui_lang ORDER BY n DESC"
                )
            ]
            per_day = [
                dict(row)
                for row in conn.execute(
                    "SELECT day, COUNT(*) AS uploads,"
                    " COUNT(DISTINCT ip_hash) AS unique_users"
                    " FROM usage_events GROUP BY day ORDER BY day DESC LIMIT ?",
                    (days,),
                )
            ]
        return {
            "total": totals["n"],
            "consented": totals["consented"] or 0,
            "outcomes": outcomes,
            "countries": countries,
            "languages": languages,
            "per_day": per_day,
        }

    def add_audit(self, username: str, ip: str, action: str, detail: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO audit_log (ts, username, ip, action, detail) VALUES (?, ?, ?, ?, ?)",
                (datetime.now(UTC).isoformat(), username, ip, action, detail),
            )

    def audit_entries(self, limit: int = 50) -> list[dict]:
        with self._connect() as conn:
            return [
                dict(row)
                for row in conn.execute(
                    "SELECT ts, username, ip, action, detail FROM audit_log"
                    " ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
            ]

    # --- admin sessions -------------------------------------------------

    MFA_PENDING_SECONDS = 10 * 60  # a session waiting for the TOTP code dies after 10 min

    def create_session(self, username: str, *, mfa_pending: bool = False,
                       mfa_setup_required: bool = False) -> tuple[str, str]:
        """Creates a login session; returns (cookie token, CSRF token).
        `mfa_pending`: the password was right, the TOTP code is still owed.
        `mfa_setup_required`: no MFA yet; only the profile page is reachable."""
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO admin_sessions (token_hash, username, csrf_token,"
                " created_at, last_seen_at, mfa_pending, mfa_setup_required)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (_token_hash(token), username, csrf, now, now, int(mfa_pending), int(mfa_setup_required)),
            )
        return token, csrf

    def session_mfa_done(self, token: str) -> None:
        """The TOTP code was accepted: the session becomes a full session."""
        with self._connect() as conn:
            conn.execute("UPDATE admin_sessions SET mfa_pending = 0 WHERE token_hash = ?", (_token_hash(token),))

    def record_login(self, username: str) -> None:
        """A completed login (password and, when set up, the TOTP code)."""
        with self._connect() as conn:
            conn.execute("UPDATE admin_users SET last_login_at = ? WHERE username = ?",
                         (datetime.now(UTC).isoformat(), username))

    def session_setup_done(self, token: str) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE admin_sessions SET mfa_setup_required = 0 WHERE token_hash = ?", (_token_hash(token),))

    def get_session(self, token: str, *, idle_seconds: float, max_age_seconds: float) -> dict | None:
        """Returns {"username", "csrf_token"} for a live session, else None.
        Expired sessions (idle or absolute) are deleted on sight."""
        if not token:
            return None
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM admin_sessions WHERE last_seen_at < ? OR created_at < ?"
                " OR (mfa_pending = 1 AND created_at < ?)",
                (now - idle_seconds, now - max_age_seconds, now - self.MFA_PENDING_SECONDS),
            )
            row = conn.execute(
                "SELECT username, csrf_token, last_seen_at, mfa_pending, mfa_setup_required"
                " FROM admin_sessions WHERE token_hash = ?",
                (_token_hash(token),),
            ).fetchone()
            if row is None:
                return None
            if now - row["last_seen_at"] > 60:  # throttle writes to once a minute
                conn.execute(
                    "UPDATE admin_sessions SET last_seen_at = ? WHERE token_hash = ?",
                    (now, _token_hash(token)),
                )
        return {
            "username": row["username"], "csrf_token": row["csrf_token"],
            "mfa_pending": bool(row["mfa_pending"]), "mfa_setup_required": bool(row["mfa_setup_required"]),
        }

    def delete_session(self, token: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM admin_sessions WHERE token_hash = ?", (_token_hash(token),))

    def set_challenge(self, token: str, challenge: str | None) -> None:
        """Stores the WebAuthn challenge the browser must sign (one per session)."""
        with self._connect() as conn:
            conn.execute("UPDATE admin_sessions SET webauthn_challenge = ? WHERE token_hash = ?",
                         (challenge, _token_hash(token)))

    def pop_challenge(self, token: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute("SELECT webauthn_challenge FROM admin_sessions WHERE token_hash = ?",
                               (_token_hash(token),)).fetchone()
            conn.execute("UPDATE admin_sessions SET webauthn_challenge = NULL WHERE token_hash = ?",
                         (_token_hash(token),))
        return row["webauthn_challenge"] if row else None


    # --- passkeys (WebAuthn) -------------------------------------------------

    def list_passkeys(self, username: str) -> list[dict]:
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT credential_id, name, sign_count, created_at FROM admin_passkeys"
                " WHERE username = ? ORDER BY created_at", (username,)
            )]

    def count_passkeys(self, username: str) -> int:
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) AS n FROM admin_passkeys WHERE username = ?",
                                (username,)).fetchone()["n"]

    def add_passkey(self, username: str, credential_id: str, public_key: bytes, sign_count: int, name: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO admin_passkeys (credential_id, username, public_key, sign_count, name, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (credential_id, username, public_key, sign_count, name, datetime.now(UTC).isoformat()),
            )

    def get_passkey(self, credential_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM admin_passkeys WHERE credential_id = ?", (credential_id,)).fetchone()
        return dict(row) if row else None

    def update_passkey_sign_count(self, credential_id: str, sign_count: int) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE admin_passkeys SET sign_count = ? WHERE credential_id = ?", (sign_count, credential_id))

    def delete_passkey(self, username: str, credential_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM admin_passkeys WHERE credential_id = ? AND username = ?",
                               (credential_id, username))
            return cur.rowcount == 1

    def delete_user_sessions(self, username: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM admin_sessions WHERE username = ?", (username,))

    # --- settings (feature switches) ----------------------------------------

    SETTING_DEFAULTS: ClassVar[dict[str, str]] = {
        "workorder_enabled": "1",
        "result_mail_enabled": "1",
        "smtp_host": "",      # smtp_host/smtp_port/mail_from are seeded from OSC_SMTP_HOST/OSC_SMTP_PORT/OSC_MAIL_FROM on first start (seed_settings)
        "smtp_port": "587",
        "mail_from": "",
        "service_partner_url": "https://fiskeroa.com/service/",
    }

    def seed_settings(self, values: dict[str, str]) -> None:
        """Writes values for keys that have never been saved (used to carry the
        OSC_SMTP_* environment variables into the admin-controlled settings)."""
        with self._connect() as conn:
            for key, value in values.items():
                if value:
                    conn.execute("INSERT OR IGNORE INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)",
                                 (key, value, datetime.now(UTC).isoformat(), "environment"))

    def get_setting(self, key: str) -> str:
        with self._connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else self.SETTING_DEFAULTS.get(key, "")

    def flag(self, key: str) -> bool:
        return self.get_setting(key) == "1"

    def set_setting(self, key: str, value: str, updated_by: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at,"
                " updated_by = excluded.updated_by",
                (key, value, datetime.now(UTC).isoformat(), updated_by),
            )

    # --- admin users ---------------------------------------------------------

    ROLES = ("admin", "readonly")

    def import_users_if_empty(self, users: dict[str, str]) -> int:
        """Bootstrap: copies the YAML users (username -> password hash) into
        the table when it is empty. Returns how many were imported."""
        if not users:
            return 0
        with self._connect() as conn:
            if conn.execute("SELECT COUNT(*) AS n FROM admin_users").fetchone()["n"]:
                return 0
            now = datetime.now(UTC).isoformat()
            conn.executemany(
                "INSERT INTO admin_users (username, password_hash, role, created_at, created_by)"
                " VALUES (?, ?, 'admin', ?, 'import')",
                [(name, pw_hash, now) for name, pw_hash in users.items()],
            )
        return len(users)

    def list_users(self) -> list[dict]:
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT u.username, u.role, u.totp_confirmed_at, u.disabled, u.created_at, u.created_by,"
                " u.password_changed_at, u.last_login_at,"
                " (SELECT COUNT(*) FROM admin_passkeys p WHERE p.username = u.username) AS passkeys"
                " FROM admin_users u ORDER BY u.username"
            )]

    def get_user(self, username: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM admin_users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None

    def create_user(self, username: str, password_hash: str, role: str, created_by: str) -> None:
        if role not in self.ROLES:
            raise ValueError(f"unknown role {role!r}")
        with self._connect() as conn:
            if conn.execute("SELECT 1 FROM admin_users WHERE username = ?", (username,)).fetchone():
                raise ValueError(f"user {username!r} already exists")
            conn.execute(
                "INSERT INTO admin_users (username, password_hash, role, created_at, created_by)"
                " VALUES (?, ?, ?, ?, ?)",
                (username, password_hash, role, datetime.now(UTC).isoformat(), created_by),
            )

    def set_password(self, username: str, password_hash: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE admin_users SET password_hash = ?, password_changed_at = ? WHERE username = ?",
                (password_hash, datetime.now(UTC).isoformat(), username),
            )

    def set_role(self, username: str, role: str) -> None:
        if role not in self.ROLES:
            raise ValueError(f"unknown role {role!r}")
        with self._connect() as conn:
            conn.execute("UPDATE admin_users SET role = ? WHERE username = ?", (role, username))

    def set_disabled(self, username: str, disabled: bool) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE admin_users SET disabled = ? WHERE username = ?", (int(disabled), username))
            if disabled:
                conn.execute("DELETE FROM admin_sessions WHERE username = ?", (username,))

    def delete_user(self, username: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM admin_passkeys WHERE username = ?", (username,))
            conn.execute("DELETE FROM admin_users WHERE username = ?", (username,))
            conn.execute("DELETE FROM admin_sessions WHERE username = ?", (username,))

    def count_active_admins(self, *, excluding: str = "") -> int:
        with self._connect() as conn:
            return conn.execute(
                "SELECT COUNT(*) AS n FROM admin_users WHERE role = 'admin' AND disabled = 0 AND username != ?",
                (excluding,),
            ).fetchone()["n"]

    def set_totp_secret(self, username: str, secret: str | None) -> None:
        """A new (unconfirmed) secret, or None to remove MFA entirely."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE admin_users SET totp_secret = ?, totp_confirmed_at = NULL, totp_last_counter = NULL"
                " WHERE username = ?",
                (secret, username),
            )

    def confirm_totp(self, username: str, counter: int) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE admin_users SET totp_confirmed_at = ?, totp_last_counter = ? WHERE username = ?",
                (datetime.now(UTC).isoformat(), counter, username),
            )

    def use_totp_counter(self, username: str, counter: int) -> bool:
        """Marks a TOTP time step as used. False if that step (or a later one)
        was already used: a code is valid exactly once."""
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE admin_users SET totp_last_counter = ? WHERE username = ?"
                " AND (totp_last_counter IS NULL OR totp_last_counter < ?)",
                (counter, username, counter),
            )
            return cur.rowcount == 1

    def stats(self, profiles: list[str] | None = None, target: str | None = None) -> dict:
        """Aggregated fleet statistics for the dashboard. Only the latest
        submission per VIN counts. Never returns VINs. `profiles` (ascending)
        and `target` come from the current requirements; without them the
        level names are sorted as strings."""
        with self._connect() as conn:
            latest = (
                "SELECT s.* FROM submissions s"
                " JOIN (SELECT vin_hash, MAX(uploaded_at) AS latest"
                "       FROM submissions GROUP BY vin_hash) m"
                " ON s.vin_hash = m.vin_hash AND s.uploaded_at = m.latest"
            )
            unique_vins = conn.execute(
                f"SELECT COUNT(*) AS n FROM ({latest})"
            ).fetchone()["n"]
            total = conn.execute("SELECT COALESCE(SUM(upload_count), 0) AS n FROM submissions").fetchone()["n"]
            verdicts = {
                row["verdict"]: row["n"]
                for row in conn.execute(
                    f"SELECT verdict, COUNT(*) AS n FROM ({latest}) GROUP BY verdict"
                )
            }
            outcomes = {
                row["outcome"]: row["n"]
                for row in conn.execute(
                    f"SELECT outcome, COUNT(*) AS n FROM ({latest}) GROUP BY outcome"
                )
            }
            trims = [
                dict(row)
                for row in conn.execute(
                    f"SELECT trim, COUNT(*) AS n FROM ({latest}) GROUP BY trim ORDER BY n DESC"
                )
            ]
            countries = [
                dict(row)
                for row in conn.execute(
                    f"SELECT country, COUNT(*) AS n FROM ({latest})"
                    " GROUP BY country ORDER BY n DESC LIMIT 20"
                )
            ]
            per_week = [
                dict(row)
                for row in conn.execute(
                    "SELECT strftime('%Y-W%W', uploaded_at) AS week, SUM(count) AS uploads,"
                    " COUNT(DISTINCT vin_hash) AS vehicles"
                    " FROM upload_events GROUP BY week ORDER BY week DESC LIMIT 26"
                )
            ]
            # Every control unit in the latest reports (requirements or not),
            # by ECU code: the most common versions and how many vehicles carry each.
            all_module_versions: dict[str, list[dict]] = {}
            for row in conn.execute(
                f"SELECT COALESCE(NULLIF(mr.code, ''), substr(mr.raw_name, 1, instr(mr.raw_name || ' - ', ' - ') - 1)) AS ecu,"
                f" mr.version, COUNT(*) AS n"
                f" FROM module_readings mr JOIN ({latest}) s ON s.id = mr.submission_id"
                f" GROUP BY ecu, mr.version ORDER BY ecu, n DESC"
            ):
                all_module_versions.setdefault(row["ecu"], []).append({"version": row["version"] or "", "count": row["n"]})
            module_versions: dict[str, list[dict]] = {}
            for row in conn.execute(
                f"SELECT mr.module_id, mr.version, COUNT(*) AS n"
                f" FROM module_readings mr"
                f" JOIN ({latest}) s ON s.id = mr.submission_id"
                f" WHERE mr.module_id IS NOT NULL"
                f" GROUP BY mr.module_id, mr.version"
                f" ORDER BY mr.module_id, n DESC"
            ):
                module_versions.setdefault(row["module_id"], []).append(
                    {"version": row["version"], "count": row["n"]}
                )
            # Level per module over the latest reports: which profile each
            # module sits at ("below" = has a number but under every profile,
            # "unknown" = no number could be read)
            module_levels: dict[str, dict[str, int]] = {}
            seen_levels: set[str] = set()
            for row in conn.execute(
                f"SELECT mr.module_id, mr.level, mr.extracted, COUNT(*) AS n"
                f" FROM module_readings mr"
                f" JOIN ({latest}) s ON s.id = mr.submission_id"
                f" WHERE mr.module_id IS NOT NULL"
                f" GROUP BY mr.module_id, mr.level, mr.extracted IS NULL"
            ):
                if row["level"] is not None:
                    key = row["level"]
                    seen_levels.add(key)
                elif row["extracted"] is not None:
                    key = "below"
                else:
                    key = "unknown"
                bucket = module_levels.setdefault(row["module_id"], {})
                bucket[key] = bucket.get(key, 0) + row["n"]
            if not profiles:
                profiles = sorted(seen_levels)
            top = profiles[-1] if profiles else None
            target = target or (profiles[-2] if len(profiles) > 1 else top)

            # "Split" cars: which modules hold back the incomplete ones.
            # zebra_22: every module >= target, some below top -> count modules below top.
            # zebra_21: modules below the target level.
            def _below(outcome: str, floor: str | None) -> dict:
                if floor is None:
                    return {"cars": 0, "modules": []}
                at_or_above = [p for p in profiles if profiles.index(p) >= profiles.index(floor)]
                placeholders = ",".join("?" * len(at_or_above))
                cars = conn.execute(
                    f"SELECT COUNT(*) AS n FROM ({latest}) WHERE outcome = ?", (outcome,)
                ).fetchone()["n"]
                modules = [
                    dict(row)
                    for row in conn.execute(
                        f"SELECT mr.module_id, COUNT(*) AS n FROM module_readings mr"
                        f" JOIN ({latest}) s ON s.id = mr.submission_id"
                        f" WHERE s.outcome = ? AND mr.module_id IS NOT NULL"
                        f" AND (mr.level IS NULL OR mr.level NOT IN ({placeholders}))"
                        f" GROUP BY mr.module_id ORDER BY n DESC",
                        (outcome, *at_or_above),
                    )
                ]
                return {"cars": cars, "modules": modules}

            split = {
                "zebra_22": _below("zebra_22", top),
                "zebra_21": _below("zebra_21", target),
            }

            # Cars on Marlin: how many are also at full top level, how many
            # have the whole Marlin package, and what the others lack.
            marlin_cars = conn.execute(f"SELECT COUNT(*) AS n FROM ({latest}) WHERE outcome = 'marlin'").fetchone()["n"]
            marlin_full_top = conn.execute(
                f"SELECT COUNT(*) AS n FROM ({latest}) WHERE outcome = 'marlin' AND complete_profile = ?", (top,)
            ).fetchone()["n"] if top else 0
            marlin_pkg_complete = conn.execute(
                f"SELECT COUNT(*) AS n FROM ({latest}) WHERE outcome = 'marlin' AND marlin_missing = ''"
            ).fetchone()["n"]
            marlin_pkg_known = conn.execute(
                f"SELECT COUNT(*) AS n FROM ({latest}) WHERE outcome = 'marlin' AND marlin_missing IS NOT NULL"
            ).fetchone()["n"]
            marlin_pkg_missing: dict[str, int] = {}
            for row in conn.execute(f"SELECT marlin_missing FROM ({latest}) WHERE outcome = 'marlin' AND marlin_missing != ''"):
                for module_id in row["marlin_missing"].split(","):
                    marlin_pkg_missing[module_id] = marlin_pkg_missing.get(module_id, 0) + 1
            marlin = {
                "cars": marlin_cars,
                "full_top": marlin_full_top,
                "both": conn.execute(
                    f"SELECT COUNT(*) AS n FROM ({latest}) WHERE outcome = 'marlin' AND complete_profile = ? AND marlin_missing = ''", (top,)
                ).fetchone()["n"] if top else 0,
                "pkg_complete": marlin_pkg_complete,
                "pkg_known": marlin_pkg_known,
                "below_top": _below("marlin", top)["modules"] if top else [],
                "pkg_missing": sorted(({"module_id": k, "n": n} for k, n in marlin_pkg_missing.items()), key=lambda m: -m["n"]),
            }
        return {
            "unique_vins": unique_vins,
            "total_submissions": total,
            "verdicts": verdicts,
            "outcomes": outcomes,
            "trims": trims,
            "countries": countries,
            "per_week": per_week,
            "module_versions": module_versions,
            "all_module_versions": all_module_versions,
            "module_levels": module_levels,
            "profiles": profiles,
            "split": split,
            "marlin": marlin,
        }
