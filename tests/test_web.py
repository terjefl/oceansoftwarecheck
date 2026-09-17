"""End-to-end tests of the web flow, including the mandatory-storage rule."""

import importlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

FIXTURE = Path(__file__).parent / "fixtures" / "olp_report.txt"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("OSC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("OSC_UPLOADS_DIR", str(tmp_path / "data" / "uploads"))
    from app import main

    importlib.reload(main)
    return TestClient(main.app), main


CONSENT = {"consent": "yes"}
FIXTURE_DATE = b"Date: 2026-08-28 18:15:16.564271"


def _dated(days_ago: int = 0, body: bytes | None = None) -> bytes:
    """The fixture with its OLP date moved to `days_ago` days before now, so
    tests do not depend on how old the fixture's real date has become."""
    when = (datetime.now(UTC) - timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S.%f").encode()
    return (body if body is not None else FIXTURE.read_bytes()).replace(FIXTURE_DATE, b"Date: " + when)


def _upload(client, consent: bool = True, body: bytes | None = None, **kwargs):
    data = CONSENT if consent else {}
    return client.post(
        "/analyze",
        files={"report": ("report.txt", body if body is not None else FIXTURE.read_bytes(), "text/plain")},
        data=data,
        **kwargs,
    )


def test_upload_without_acceptance_is_refused_and_stores_nothing(client):
    c, main = client
    response = _upload(c, consent=False)
    assert response.status_code == 422
    assert "must accept" in response.text
    assert "VCF1ZBE20PG099999" not in response.text
    assert main.database.stats()["unique_vins"] == 0
    assert not Path(main.UPLOADS_DIR).exists()


def test_upload_stores_submission_file_and_all_module_readings(client):
    c, main = client
    response = _upload(c, consent=True, headers={"CF-IPCountry": "NO"})
    assert response.status_code == 200
    import sqlite3

    conn = sqlite3.connect(main.database.path)
    conn.row_factory = sqlite3.Row
    sub = conn.execute("SELECT * FROM submissions").fetchone()
    assert (sub["trim"], sub["outcome"], sub["complete_profile"], sub["top_evidence"], sub["country"]) == (
        "Z", "zebra_21", None, "2.1", "NO"
    )
    assert sub["report_date"].startswith("2026-08-28")
    readings = conn.execute("SELECT * FROM module_readings ORDER BY rowid").fetchall()
    assert len(readings) == 37  # every ECU block, not only the eight with requirements
    vcu = next(r for r in readings if r["code"] == "VCU")
    assert (vcu["module_id"], vcu["extracted"], vcu["level"], vcu["evidence_level"], vcu["section"]) == (
        "VCU", 21, "2.1", "2.1", "POWERTRAIN"
    )
    esp = next(r for r in readings if r["code"] == "ESP")
    assert (esp["software"], esp["bootloader"]) == ("FM292045S020J", "FM292045B020B")
    assert sum(1 for r in readings if r["status"] == "extra") == 29
    stats = main.database.stats()
    assert stats["unique_vins"] == 1
    assert stats["total_submissions"] == 1
    stored = list(Path(main.UPLOADS_DIR).iterdir())
    assert len(stored) == 1
    assert "VCF1ZBE20PG099999" in stored[0].name

    # Same VIN again -> still 1 unique car, 2 submissions
    _upload(c, consent=True)
    stats = main.database.stats()
    assert stats["unique_vins"] == 1
    assert stats["total_submissions"] == 2


def test_invalid_file_shows_error(client):
    c, _ = client
    response = c.post("/analyze", files={"report": ("junk.txt", b"nothing useful here", "text/plain")}, data=CONSENT,
    )
    assert response.status_code == 422


def test_parse_error_is_fully_translated(client):
    """Regression: the error reason must follow the page language, not be hardcoded Norwegian."""
    c, _ = client
    english = c.post("/analyze?lang=en", files={"report": ("junk.txt", b"nothing useful here", "text/plain")}, data=CONSENT,
    )
    assert "Could not find the heading" in english.text
    assert "Fant ikke overskriften" not in english.text

    german = c.post(
        "/analyze?lang=de",
        files={"report": ("junk.txt", b"nothing useful here", "text/plain")},
        data=CONSENT,
    )
    assert "wurde nicht gefunden" in german.text


def test_language_switch_on_error_page_redirects_home(client):
    """The language picker on the error page does GET /analyze?lang=... — must not 405."""
    c, _ = client
    response = c.get("/analyze?lang=de", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/?lang=de"
    followed = c.get("/analyze?lang=de")
    assert followed.status_code == 200
    assert "Mein Auto prüfen" in followed.text


def test_stats_and_privacy_pages_render(client):
    c, _ = client
    assert c.get("/stats").status_code == 200
    assert c.get("/privacy").status_code == 200
    assert c.get("/healthz").json() == {"status": "ok"}


def test_result_page_survives_language_switch_and_reload(client):
    """POST /analyze redirects to GET /vehicle/<key> (the permanent link); language switch and refresh work."""
    c, _ = client
    response = _upload(c)
    assert response.status_code == 200
    assert "/vehicle/" in str(response.url)

    # Refresh (GET of the same URL) works
    again = c.get(str(response.url))
    assert again.status_code == 200 and "VCF1ZBE20PG099999" in again.text

    # Language switch via ?lang= renders the same result in the new language
    german = c.get(str(response.url) + "?lang=de")
    assert german.status_code == 200
    assert "Ergebnis für VIN" in german.text

    # Old-style 30-minute links -> front page with an explanation, not a silent redirect
    gone = c.get("/result/finnesikke?lang=en")
    assert gone.status_code == 410
    assert "This result link is no longer in use" in gone.text
    assert c.get("/pdf/finnesikke").status_code == 410 and c.get("/pdf/finnesikke/workorder").status_code == 410
    # Result pages carry the VIN and must not be cached anywhere
    assert again.headers["cache-control"] == "private, no-store"


def test_usage_logged_without_vin_and_without_ip(client):
    """Usage is counted per upload (parse errors too) — never with VIN or raw IP."""
    c, main = client
    headers = {"CF-IPCountry": "NO", "Accept-Language": "nb-NO,nb;q=0.9"}
    response = _upload(c, headers=headers)
    assert response.status_code == 200
    # Parse errors are counted too
    c.post("/analyze", files={"report": ("junk.txt", b"garbage", "text/plain")}, data=CONSENT, headers=headers)

    usage = main.database.usage_stats()
    assert usage["total"] == 2
    assert usage["outcomes"] == {"zebra": 1, "parse_error": 1}
    assert usage["countries"][0]["country"] == "NO"
    assert usage["languages"][0]["ui_lang"] == "nb"
    assert usage["per_day"][0]["unique_users"] == 1  # same client both times

    # Raw IP or VIN must never appear in the usage table
    import sqlite3

    conn = sqlite3.connect(main.database.path)
    rows = conn.execute("SELECT * FROM usage_events").fetchall()
    blob = str(rows)
    assert "VCF1ZBE20PG099999" not in blob
    assert "testclient" not in blob and "127.0.0.1" not in blob

    assert main.database.stats()["unique_vins"] == 1


def test_language_negotiation(client):
    c, _ = client
    norsk = c.get("/", headers={"accept-language": "nb-NO,nb;q=0.9"})
    assert "Sjekk bilen min" in norsk.text
    deutsch = c.get("/?lang=de")
    assert "Mein Auto prüfen" in deutsch.text
    assert deutsch.cookies.get("lang") == "de"


def test_upload_rate_limit_ignores_client_supplied_forwarded_for(client):
    """Only the configured proxy header (CF-Connecting-IP) identifies the
    client. Cloudflare appends to a client-supplied X-Forwarded-For, so its
    first element must never be used for rate limiting."""
    c, main = client
    fixture = FIXTURE.read_bytes()

    codes = []
    for i in range(main.RATE_LIMIT_UPLOADS + 2):
        response = c.post("/analyze", files={"report": ("r.txt", fixture, "text/plain")}, data=CONSENT,
            headers={"X-Forwarded-For": f"10.0.0.{i}, 203.0.113.5"},
            follow_redirects=False,
        )
        codes.append(response.status_code)
    assert codes[: main.RATE_LIMIT_UPLOADS] == [303] * main.RATE_LIMIT_UPLOADS
    assert codes[main.RATE_LIMIT_UPLOADS:] == [429, 429]

    # A different CF-Connecting-IP is a different client and is not blocked
    response = c.post("/analyze", files={"report": ("r.txt", fixture, "text/plain")}, data=CONSENT,
        headers={"CF-Connecting-IP": "198.51.100.42"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    # ...and expired/blocked entries do not accumulate one key per spoofed value
    assert set(main._upload_hits) <= {"testclient", "198.51.100.42"}


def test_usage_ip_hash_is_keyed_and_not_reversible(client):
    """The daily unique-user hash must not be a plain sha256 over a public salt
    (that is brute-forceable over the IPv4 space)."""
    import hashlib
    from datetime import datetime

    c, main = client
    c.post("/analyze", files={"report": ("r.txt", FIXTURE.read_bytes(), "text/plain")}, data=CONSENT,
           headers={"CF-Connecting-IP": "203.0.113.77"})
    import sqlite3

    stored = sqlite3.connect(main.database.path).execute(
        "SELECT ip_hash FROM usage_events"
    ).fetchone()[0]
    day = datetime.now(UTC).strftime("%Y-%m-%d")
    public_scheme = hashlib.sha256(f"marlin-{day}|203.0.113.77".encode()).hexdigest()[:16]
    assert stored != public_scheme
    assert len(stored) == 16
    # Same client on the same day -> same hash (unique-user counting still works)
    c.post("/analyze", files={"report": ("r.txt", FIXTURE.read_bytes(), "text/plain")}, data=CONSENT,
           headers={"CF-Connecting-IP": "203.0.113.77"})
    assert main.database.usage_stats()["per_day"][0]["unique_users"] == 1
    # A new key (restart / day rollover) yields a different hash for the same IP
    main._usage_key["day"] = ""
    c.post("/analyze", files={"report": ("r.txt", FIXTURE.read_bytes(), "text/plain")}, data=CONSENT,
           headers={"CF-Connecting-IP": "203.0.113.77"})
    assert main.database.usage_stats()["per_day"][0]["unique_users"] == 2


def test_slow_pdf_does_not_block_other_requests(client, monkeypatch):
    """Parsing runs in the threadpool: while one upload is being parsed, the
    event loop must still serve /healthz. The TestClient is used as a context
    manager so both requests share ONE event loop (otherwise each request gets
    its own portal and blocking would go unnoticed)."""
    import threading
    import time

    _, main = client
    started = threading.Event()
    release = threading.Event()
    original_parse = main.parse_report

    def slow_parse(data, filename):
        started.set()
        release.wait(timeout=5)
        return original_parse(data, filename)

    monkeypatch.setattr(main, "parse_report", slow_parse)

    result = {}
    with TestClient(main.app) as shared:

        def upload():
            result["status"] = shared.post(
                "/analyze", files={"report": ("r.txt", FIXTURE.read_bytes(), "text/plain")},
                data=CONSENT, follow_redirects=False,
            ).status_code

        worker = threading.Thread(target=upload)
        worker.start()
        assert started.wait(timeout=5)
        t0 = time.perf_counter()
        health = shared.get("/healthz")
        elapsed = time.perf_counter() - t0
        release.set()
        worker.join(timeout=10)
    assert health.status_code == 200
    assert elapsed < 2, f"/healthz was blocked for {elapsed:.1f}s while a PDF was being parsed"
    assert result["status"] == 303


@pytest.fixture()
def client_with_config(tmp_path, monkeypatch):
    """Like `client`, but with a writable copy of the requirements file."""
    import shutil

    config = tmp_path / "config"
    config.mkdir()
    shutil.copy(Path(__file__).parent.parent / "requirements.example.yaml", config / "requirements.yaml")
    monkeypatch.setenv("OSC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("OSC_UPLOADS_DIR", str(tmp_path / "data" / "uploads"))
    monkeypatch.setenv("OSC_REQUIREMENTS_PATH", str(config / "requirements.yaml"))
    from app import main

    importlib.reload(main)
    return TestClient(main.app), main, config / "requirements.yaml"


def test_corrupt_requirements_keeps_last_good_and_degrades_healthz(client_with_config):
    c, _main, path = client_with_config
    good = path.read_text()
    assert c.get("/healthz").status_code == 200
    assert "2026-09-15" in _upload(c).text

    path.write_text("modules: [\n")  # a bad edit on the host
    health = c.get("/healthz")
    assert health.status_code == 503
    assert health.json()["status"] == "degraded"
    # Analyses continue on the last valid set instead of failing with 500
    response = _upload(c)
    assert response.status_code == 200
    assert "2026-09-15" in response.text
    assert c.get("/").status_code == 200

    path.unlink()  # mount gone entirely
    assert c.get("/healthz").status_code == 503
    assert _upload(c).status_code == 200

    path.write_text(good)
    assert c.get("/healthz").status_code == 200


def test_corrupt_requirements_at_startup_gives_503_not_500(tmp_path, monkeypatch):
    config = tmp_path / "config"
    config.mkdir()
    (config / "requirements.yaml").write_text("not: [valid")
    monkeypatch.setenv("OSC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("OSC_UPLOADS_DIR", str(tmp_path / "data" / "uploads"))
    monkeypatch.setenv("OSC_REQUIREMENTS_PATH", str(config / "requirements.yaml"))
    from app import main

    importlib.reload(main)
    c = TestClient(main.app, raise_server_exceptions=False)
    assert c.get("/healthz").status_code == 503
    response = _upload(c)
    assert response.status_code == 503
    assert "requirements file is currently unavailable" in response.text


def test_oversized_upload_rejected_by_content_length_and_by_chunked_read(client):
    c, main = client
    limit = main.MAX_REPORT_BYTES
    # Far over the limit: the middleware answers from Content-Length alone
    huge = c.post("/analyze", files={"report": ("big.txt", b"x" * (limit + 200 * 1024), "text/plain")}, data=CONSENT)
    assert huge.status_code == 413
    assert "larger than the 15 MB limit" in huge.text
    # Just over the limit (inside the multipart slack): caught by the chunked read
    just_over = c.post("/analyze", files={"report": ("big.txt", b"x" * (limit + 1), "text/plain")}, data=CONSENT)
    assert just_over.status_code == 413
    # Under the limit still goes through the parser (and is rejected as not a report)
    assert c.post("/analyze", files={"report": ("r.txt", b"x" * 1024, "text/plain")}, data=CONSENT).status_code == 422


def test_bad_pdf_error_hides_library_internals(client):
    c, _ = client
    response = c.post("/analyze?lang=en", files={"report": ("r.pdf", b"%PDF-1.7 garbage", "application/pdf")}, data=CONSENT)
    assert response.status_code == 422
    assert "The PDF content could not be read." in response.text
    assert "The PDF content could not be read. (" not in response.text
    for leak in ("pdfminer", "pdfplumber", "Traceback", "PSEOF", "No /Root"):
        assert leak not in response.text


def test_pdf_download_is_not_cacheable(client):
    pytest.importorskip("weasyprint")
    c, _ = client
    response = _upload(c)
    pdf = c.get(str(response.url) + "/pdf")
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.headers["cache-control"] == "private, no-store"


def test_marlin_car_result_page_and_statistics(client):
    """A car already on Marlin gets the informational verdict on the page and
    is counted separately in the public statistics."""
    c, main = client
    fixture = Path(__file__).parent / "fixtures" / "olp_report_marlin_bcm41.txt"
    response = c.post("/analyze?lang=en", files={"report": ("r.txt", fixture.read_bytes(), "text/plain")}, data=CONSENT)
    assert response.status_code == 200
    assert "Already on Marlin" in response.text
    assert "can be updated directly to Marlin" not in response.text
    assert "Marlin does not update every module" in response.text
    assert "BCM \u2013 Body Control Module: is at version 41 (2.1 level) and needs to be updated to 42 (2.2 level)" in response.text
    assert "Your car is on Marlin. Update the modules above" in response.text
    # The Marlin package: this car only got VCU 24
    assert "Not complete \u2013 3 of 4 modules the Marlin update installs are not at the Marlin level" in response.text
    assert "PDU \u2013 Power Distribution Unit: is at version 3900 and needs to be updated to 4000 (Marlin level)" in response.text
    assert "Modules the Marlin update installs" in response.text and "Your car has received Marlin, but not every module" in response.text
    assert 'href="https://fiskeroa.com/service/" target="_blank"' in response.text

    full = Path(__file__).parent / "fixtures" / "olp_report_marlin.txt"
    page = c.post("/analyze?lang=en", files={"report": ("r.txt", full.read_bytes(), "text/plain")}, data=CONSENT).text
    assert "Complete \u2013 all 4 modules the Marlin update installs are at the Marlin level" in page
    assert "with every Marlin module in place" in page and "Have them updated" not in page

    stats = main.database.stats()
    assert stats["verdicts"] == {"marlin": 2}
    assert stats["outcomes"] == {"marlin": 2}
    page = c.get("/stats?lang=en")
    assert "On Marlin" in page.text and "Vehicles per software status" in page.text
    assert main.database.usage_stats()["outcomes"] == {"marlin": 2}


def test_security_headers_and_no_inline_scripts(client):
    c, _ = client
    for path in ("/", "/stats", "/privacy"):
        response = c.get(path)
        assert response.status_code == 200
        csp = response.headers["content-security-policy"]
        assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert "onclick=" not in response.text and "onchange=" not in response.text
        assert "<script>" not in response.text  # only /static/app.js
    assert c.get("/static/app.js").status_code == 200


def test_front_page_shows_variant_levels_for_bms(client):
    c, _ = client
    page = c.get("/?lang=en").text
    assert "≥ \u2013" not in page
    # Variant levels per software line, once per profile column and once for the Marlin column
    assert page.count("≥ 21 <span class=\"crit\">[NMC]</span> / ≥ 15 <span class=\"crit\">[LFP]</span>") == 4
    # One column per profile plus the Marlin requirement column
    for heading in ("SW 2.0", "SW 2.1", "SW 2.2", "Marlin requirement"):
        assert heading in page


def test_empty_version_field_is_explained_on_the_result_page(client):
    c, _ = client
    text = FIXTURE.read_text().replace("Supplier SW Version: VCU039021", "Supplier SW Version:")
    response = c.post("/analyze?lang=en", files={"report": ("r.txt", text.encode(), "text/plain")}, data=CONSENT)
    assert response.status_code == 200
    assert "Version field empty in the report" in response.text
    assert "Version not recognized" not in response.text


def test_how_it_works_page_in_every_language(client):
    """The public 'how it works' page: linked from the top menu, rendered
    from structured locale content, complete in all seven languages."""
    import json

    from app.i18n import LOCALES_DIR, SUPPORTED

    c, _ = client
    en = json.loads((LOCALES_DIR / "en.json").read_text(encoding="utf-8"))
    shape = [(len(s["paragraphs"]), len(s.get("bullets", []))) for s in en["how_sections"]]
    assert len(shape) == 9

    for lang in SUPPORTED:
        table = json.loads((LOCALES_DIR / f"{lang}.json").read_text(encoding="utf-8"))
        for key in ("nav_how", "how_title", "how_intro", "how_sections"):
            assert key in table, (lang, key)
        # same structure in every language: no section, paragraph or bullet lost in translation
        assert [(len(s["paragraphs"]), len(s.get("bullets", []))) for s in table["how_sections"]] == shape, lang

        page = c.get(f"/how-it-works?lang={lang}")
        assert page.status_code == 200
        assert table["how_title"] in page.text
        assert table["how_sections"][-1]["paragraphs"][0][:40] in page.text
        assert f'href="/how-it-works">{table["nav_how"]}</a>' in c.get(f"/?lang={lang}").text
        assert "<script>" not in page.text  # CSP: no inline scripts


def test_heavy_jobs_are_limited():
    """Report parsing and PDF rendering go through a semaphore so a burst of
    uploads queues instead of fanning out over the whole threadpool."""
    import asyncio
    import threading
    import time

    from app import main

    running = 0
    peak = 0
    lock = threading.Lock()

    def job():
        nonlocal running, peak
        with lock:
            running += 1
            peak = max(peak, running)
        time.sleep(0.05)
        with lock:
            running -= 1

    async def burst():
        await asyncio.gather(*(main._run_heavy(job) for _ in range(main.MAX_HEAVY_JOBS * 3)))

    asyncio.run(burst())
    assert 0 < peak <= main.MAX_HEAVY_JOBS


def test_permanent_vehicle_link(client):
    """Every result page carries a permanent /vehicle/<key> link that shows the
    car's latest report (evaluated against the current requirements) straight
    from the database, keeps the same key across uploads of the same VIN,
    serves a PDF, and rejects unknown keys."""
    import re

    c, _ = client
    page = _upload(c, headers={"x-forwarded-proto": "https", "host": "check.example"}).text
    m = re.search(r"https://check\.example/vehicle/([A-Za-z0-9_-]{16,})", page)
    assert m, "permanent link missing on the result page"
    key = m.group(1)
    assert "Permanent link for this car" in page

    vehicle = c.get(f"/vehicle/{key}")
    assert vehicle.status_code == 200
    assert "2.1 zebra" in vehicle.text and "Latest report for this car" in vehicle.text
    assert vehicle.headers["cache-control"] == "private, no-store"
    assert f"/vehicle/{key}/pdf" in vehicle.text

    # A second upload of the same VIN keeps the key and the link now shows the new report
    body = FIXTURE.read_bytes().replace(b"BCM395021", b"BCM395030")
    page2 = _upload(c, body=body).text
    assert f"/vehicle/{key}" in page2
    assert "Clean 2.1" in c.get(f"/vehicle/{key}").text or "2.1 fully installed" in c.get(f"/vehicle/{key}").text

    pdf = c.get(f"/vehicle/{key}/pdf")
    assert pdf.status_code == 200 and pdf.headers["content-type"] == "application/pdf"
    assert pdf.content[:5] == b"%PDF-"

    unknown = c.get("/vehicle/" + "x" * 22)
    assert unknown.status_code == 404 and "no vehicle behind this link" in unknown.text
    assert c.get("/vehicle/short").status_code == 404


def test_public_stats_page_is_short(client):
    """The public dashboard keeps outcomes, level per module, trims and
    countries; the working-group detail moved to /admin/analytics."""
    c, _ = client
    _upload(c)
    page = c.get("/stats?lang=en").text
    assert "Vehicles per software status" in page and "Software level per module" in page
    assert "Trims" in page and "Countries" in page
    for gone in ("Uploads over time", "Movement in the fleet", "What holds the split cars back",
                 "Every control unit in the reports"):
        assert gone not in page
    assert "VCF1ZBE20PG099999" not in page


def test_result_page_layout_follows_the_working_group(client):
    """Module list before the level lines, only the highest complete level in
    green with every level above it in red, counts of modules that do NOT meet,
    module lines with code first and both versions, the multi-step note, the
    recommendation and the red contact line. A 2.2 zebra never gets a green
    Marlin line."""
    c, _ = client
    body = FIXTURE.read_bytes().replace(b"BCM395021", b"BCM395030")  # clean 2.1 car
    page = _upload(c, body=body).text
    assert "SW 2.0" not in page.split("Requirements version")[0]  # 2.0 line hidden for a full 2.1 car
    assert "SW 2.1</strong>: Complete" in page and "SW 2.2</strong>: Not complete \u2013 7 of 8 modules do not meet" in page
    assert page.index("BCM \u2013 Body Control Module: is at version 30 (2.1 level) and needs to be updated to 42 (2.2 level)") < page.index("SW 2.1</strong>")
    assert "The following modules are recommended to be updated to meet the minimum 2.2 requirements." in page
    assert "multi-step installation process" in page
    assert "Update the modules above so that your car meets the minimum 2.2 requirement, then update to Marlin. You could update to Marlin alone, but it is not recommended." in page
    assert '<a href="https://fiskeroa.com/service/" target="_blank" rel="noopener">Contact your service provider.</a>' in page
    assert "\u2705 <strong>Marlin</strong>: Ready for the update" in page
    assert "You can save this address" in page

    zebra22 = body.replace(b"VCU039021", b"VCU039023")  # one module lifted to 2.2 -> 2.2 zebra
    page = _upload(c, body=zebra22).text
    assert "2.2 zebra" in page and "\u274c <strong>Marlin</strong>: Not ready" in page
    assert "must complete 2.2 before it can be updated to Marlin" in page

    full22 = Path(__file__).parent / "fixtures" / "olp_report_22_full.txt"
    page = _upload(c, body=full22.read_bytes()).text
    assert "SW 2.1</strong>" not in page.split("Requirements version")[0] and "SW 2.2</strong>: Complete" in page
    assert "recommended to be updated" not in page
    assert "regional or country liaison" in page and "meets the minimum 2.2 requirement and can be updated to Marlin" in page
    assert "Modules the Marlin update installs" not in page  # only shown to cars on Marlin


def test_pdf_uses_coloured_marks_and_no_link(client):
    """The PDF has no emoji font, so it renders coloured ticks and crosses, and
    the permanent link stays out of it."""
    from app import main

    c, _ = client
    body = FIXTURE.read_bytes().replace(b"BCM395021", b"BCM395030")
    key = _upload(c, body=body, follow_redirects=False).headers["location"].rsplit("/", 1)[1]
    report, evaluation, _submission = main._vehicle_by_key(key)
    html = main.templates.get_template("pdf.html").render(
        lang="en", t=main.translator("en"), report=report, evaluation=evaluation,
        for_pdf=True, generated_at="now", service_url=main.database.get_setting("service_partner_url"),
    )
    assert '<span class="mark ok">\u2713</span>' in html and '<span class="mark bad">\u2717</span>' in html
    assert "\u2705" not in html and "\u274c" not in html
    assert "/vehicle/" not in html and "Permanent link" not in html
    assert 'href="https://fiskeroa.com/service/"' in html and 'Contact your service provider.</a> <span class="mono">https://fiskeroa.com/service/</span>' in html


def test_changes_since_previous_report_and_report_age(client):
    """A second upload of the same VIN shows what changed (outcome and every
    module whose version differs); the permanent link warns when the report
    is old."""
    import re

    c, main = client
    first = _upload(c).text
    assert "Since your previous report" not in first and "Nothing has changed" not in first
    same = _upload(c).text
    assert "Since your previous report" not in same  # identical re-upload: merged, so still one stored state
    body = FIXTURE.read_bytes().replace(b"BCM395021", b"BCM395030").replace(b"ICC390047", b"ICC390C49")
    page = _upload(c, body=body).text
    assert "Since your previous report" in page
    assert "Result: 2.1 zebra → Clean 2.1" in page
    assert "BCM: BCM395021 → BCM395030" in page and "ICC: ICC390047 → ICC390C49" in page

    key = re.search(r"/vehicle/([A-Za-z0-9_-]{16,})", page).group(1)
    vehicle = c.get(f"/vehicle/{key}").text
    assert "Since your previous report" in vehicle and "days old" not in vehicle

    # The age is the OLP report date's, not the upload's: a 100 day old
    # export is 100 days old however recently it was uploaded. Without a
    # readable report date (or with one in the future, from a wrong laptop
    # clock) the upload time is used instead.
    # Checked on a car with a single stored report, so backdating the row
    # cannot make another row the car's latest.
    single = _upload(c, body=_dated(0).replace(b"VCF1ZBE20PG099999", b"VCF1ZBE20PG099998"), follow_redirects=False)
    key = single.headers["location"].rsplit("/", 1)[1]

    def _set(report_date: str, uploaded_at: str) -> str:
        with main.database._connect() as conn:
            conn.execute("UPDATE submissions SET report_date = ?, uploaded_at = ? WHERE vin = ?",
                         (report_date, uploaded_at, "VCF1ZBE20PG099998"))
        return c.get(f"/vehicle/{key}").text

    now = datetime.now(UTC).isoformat()
    hundred = (datetime.now(UTC) - timedelta(days=100)).strftime("%Y-%m-%d %H:%M:%S.%f")
    assert "This report is 100 days old" in _set(hundred, now)
    assert "days old" not in _set("", now)
    assert re.search(r"This report is \d+ days old", _set("", "2026-01-01T10:00:00+00:00"))
    assert re.search(r"This report is \d+ days old", _set("not a date", "2026-01-01T10:00:00+00:00"))
    assert "days old" not in _set("2099-01-01 10:00:00.000000", now)
    assert re.search(r"This report is \d+ days old", _set("2026-01-01 10:00:00.000000", now))


def test_older_report_does_not_replace_the_current_one(client):
    """A wrong file picked by mistake, an OLP export older than the car's
    current report, is analysed but not stored: the vehicle page shows the
    stored report with a note naming both dates, the register and the files
    are untouched. A report dated the same or later is stored as usual, and
    reports without a readable date cannot be compared and are stored."""
    c, main = client
    _upload(c, body=_dated(1))
    files_before = set(Path(main.UPLOADS_DIR).iterdir())
    older = _dated(30, FIXTURE.read_bytes().replace(b"BCM395021", b"BCM395030"))
    response = _upload(c, body=older, follow_redirects=False)
    assert response.status_code == 303 and "?older=" in response.headers["location"]
    page = c.get(response.headers["location"]).text
    assert "is an older report (" in page and "The stored report is shown" in page
    assert "BCM395021" in page and "BCM395030" not in page  # the stored report, not the older file
    assert "Since your previous report" not in page
    history = main.database.vehicle_history("VCF1ZBE20PG099999")
    assert len(history) == 1 and history[0]["upload_count"] == 1
    assert set(Path(main.UPLOADS_DIR).iterdir()) == files_before
    assert main.database.usage_stats()["outcomes"].get("older_report") == 1  # counted as usage, not as a report

    # The note comes from the query string, which is validated: junk is ignored
    key = response.headers["location"].split("/vehicle/")[1].split("?")[0]
    assert "older report" not in c.get(f"/vehicle/{key}?older=<script>").text

    # Same date: stored (a new reading of the same day), later date: stored
    assert len(main.database.vehicle_history("VCF1ZBE20PG099999")) == 1
    _upload(c, body=_dated(0, FIXTURE.read_bytes().replace(b"BCM395021", b"BCM395030")))
    assert len(main.database.vehicle_history("VCF1ZBE20PG099999")) == 2
    undated = _dated(0).replace(b"Date: ", b"Was: ")
    assert b"Date:" not in undated
    _upload(c, body=undated)
    assert len(main.database.vehicle_history("VCF1ZBE20PG099999")) == 3


def test_work_order_pdf_lists_modules_in_order(client):
    """The work order PDF lists the modules below 2.1 first, then the rest
    below 2.2, and is offered only when there is something to update."""
    from app import main

    c, _ = client
    key = _upload(c, follow_redirects=False).headers["location"].rsplit("/", 1)[1]  # BCM 21: 2.1 zebra
    page = c.get(f"/vehicle/{key}").text
    assert f"/vehicle/{key}/workorder" in page
    _report, evaluation, _submission = main._vehicle_by_key(key)
    rows = main._workorder_rows(evaluation)
    assert rows[0]["code"] == "BCM" and rows[0]["profile"] == "2.1" and rows[0]["needed"] == 30
    assert {r["code"] for r in rows[1:]} == {"ESP", "IBS", "ECC", "MCU_F", "MCU_R", "VCU"} and all(r["profile"] == "2.2" for r in rows[1:])
    pdf = c.get(f"/vehicle/{key}/workorder")
    assert pdf.status_code == 200 and pdf.content[:5] == b"%PDF-" and "checklist" in pdf.headers["content-disposition"]

    full22 = Path(__file__).parent / "fixtures" / "olp_report_22_full.txt"
    page = _upload(c, body=full22.read_bytes()).text
    assert "/workorder" not in page  # nothing to update
    assert c.get("/vehicle/nonexistent-key-00000000/workorder").status_code == 404


def test_identical_reupload_is_merged_and_counted(client):
    """Uploading the same report again refreshes the vehicle's latest row
    instead of adding one: one row, upload_count 2, the old file gone, totals
    still counting every upload. A different report adds a row."""
    c, main = client
    _upload(c, body=_dated(2))
    first_files = set(Path(main.UPLOADS_DIR).iterdir())
    _upload(c, body=_dated(2))
    history = main.database.vehicle_history("VCF1ZBE20PG099999")
    assert len(history) == 1 and history[0]["upload_count"] == 2
    files = set(Path(main.UPLOADS_DIR).iterdir())
    assert len(files) == 1 and files != first_files  # the newer file replaced the older
    stats = main.database.stats()
    assert stats["total_submissions"] == 2 and stats["unique_vins"] == 1
    # A new OLP reading with the same versions is still merged, but the row
    # follows the file: the report date is the newer reading's.
    first_date = history[0]["report_date"]
    _upload(c, body=_dated(1))
    history = main.database.vehicle_history("VCF1ZBE20PG099999")
    assert len(history) == 1 and history[0]["upload_count"] == 3
    assert history[0]["report_date"] > first_date
    _upload(c, body=_dated(0, FIXTURE.read_bytes().replace(b"BCM395021", b"BCM395030")))
    history = main.database.vehicle_history("VCF1ZBE20PG099999")
    assert len(history) == 2 and history[0]["upload_count"] == 1 and history[1]["upload_count"] == 3
    assert main.database.fleet_vehicles()[0]["uploads"] == 4


def test_failed_database_write_leaves_no_orphaned_file(client, monkeypatch):
    """The file is written before the database row. If the row cannot be
    written, the file is removed again: nothing in the uploads directory
    without a submission to find it by."""
    _c, main = client

    def boom(*_args, **_kwargs):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(main.database, "store_upload", boom)
    from fastapi.testclient import TestClient

    lenient = TestClient(main.app, raise_server_exceptions=False)
    assert lenient.post(
        "/analyze", files={"report": ("report.txt", FIXTURE.read_bytes(), "text/plain")}, data=CONSENT,
    ).status_code == 500
    uploads = Path(main.UPLOADS_DIR)
    assert not uploads.exists() or not any(uploads.iterdir())
    assert main.database.vehicle_history("VCF1ZBE20PG099999") == []


def test_front_page_links_to_the_association(client):
    c, _ = client
    page = c.get("/?lang=en").text
    assert 'href="https://fiskeroa.com/" target="_blank" rel="noopener">Fisker Owners Association</a>' in page
    assert "is for members of" in page and "requires an active FOA membership" in page and "what remains before Marlin." in page


def test_send_result_by_email(client, monkeypatch):
    """The result page offers 'send me this result' when a relay is configured:
    the permanent link and the PDF go to the typed address, which is not
    stored; invalid addresses and bursts are refused; the switch turns it off."""
    import re

    from app import mail

    c, main = client
    sent = []
    main.database.set_setting("smtp_host", "relay.example", "test")
    monkeypatch.setattr(mail, "send", lambda relay, to, subject, text, attachments=None: sent.append((to, subject, text, attachments)))
    key = _upload(c, follow_redirects=False).headers["location"].rsplit("/", 1)[1]
    page = c.get(f"/vehicle/{key}").text
    assert 'name="email"' in page and f'action="/vehicle/{key}/email"' in page

    bad = c.post(f"/vehicle/{key}/email", data={"email": "not-an-address"}, follow_redirects=False)
    assert bad.headers["location"] == f"/vehicle/{key}?mail=invalid"
    ok = c.post(f"/vehicle/{key}/email", data={"email": "member@example.org"}, follow_redirects=False,
                headers={"x-forwarded-proto": "https", "host": "check.example"})
    assert ok.headers["location"] == f"/vehicle/{key}?mail=sent"
    to, subject, text, attachments = sent[-1]
    assert to == "member@example.org" and "VCF1ZBE20PG099999" in subject
    assert re.search(r"https://check\.example/vehicle/[A-Za-z0-9_-]{16,}", text) and "2.1 zebra" in text
    assert attachments[0][0].endswith(".pdf") and attachments[0][1][:5] == b"%PDF-" and len(attachments) == 1
    assert "{checklist}" not in text
    assert "Sent. Check your inbox" in c.get(f"/vehicle/{key}?mail=sent").text
    assert 'name="checklist"' in page
    c.post(f"/vehicle/{key}/email", data={"email": "member@example.org", "checklist": "1"}, follow_redirects=False)
    _, _, text, attachments = sent[-1]
    assert [a[0] for a in attachments] == ["ocean-software-check_VCF1ZBE20PG099999.pdf", "ocean-software-check_checklist_VCF1ZBE20PG099999.pdf"]
    assert "checklist for service providers" in text and "{checklist}" not in text
    with main.database._connect() as conn:  # nothing about the address is stored anywhere
        for table in ("submissions", "usage_events", "audit_log"):
            assert not any("member@example.org" in str(tuple(r)) for r in conn.execute(f"SELECT * FROM {table}"))

    for _ in range(main.MAIL_LIMIT):
        c.post(f"/vehicle/{key}/email", data={"email": "member@example.org"}, follow_redirects=False)
    assert c.post(f"/vehicle/{key}/email", data={"email": "member@example.org"}, follow_redirects=False).headers["location"].endswith("?mail=limit")

    main.database.set_setting("result_mail_enabled", "0", "test")
    assert 'name="email"' not in c.get(f"/vehicle/{key}").text
    assert c.post(f"/vehicle/{key}/email", data={"email": "member@example.org"}).status_code == 404


def test_incomplete_report_is_flagged(client):
    """A required module with NA (no answer during the scan) gives a warning
    box, a suffix on the outcome and a module line asking for a new scan; the
    outcome itself stays pessimistic. The e-mail carries the note too."""
    import unittest.mock as um

    from app import mail

    c, main = client
    sent = []
    main.database.set_setting("smtp_host", "relay.example", "test")
    body = FIXTURE.read_bytes().replace(b"Supplier SW Version: ECC395 24", b"Supplier SW Version: NA")
    assert body != FIXTURE.read_bytes()
    location = _upload(c, body=body, follow_redirects=False).headers["location"]
    page = c.get(location + "?lang=en").text
    assert "The report has no readable version for ECC" in page and "(based on an incomplete report)" in page
    assert "ECC \u2013 Electrical Climate Controller: Version field empty in the report. No version could be read" in page
    assert "2.1 zebra" in page
    with um.patch.object(mail, "send", lambda relay, to, subject, text, attachments=None: sent.append(text)):
        c.post(location + "/email", data={"email": "m@example.org"}, follow_redirects=False)
    assert sent and "no readable version for ECC" in sent[-1] and "(based on an incomplete report)" in sent[-1]
    # A clean scan of the same car replaces the incomplete one on the permanent link
    clean = c.get(_upload(c, follow_redirects=False).headers["location"] + "?lang=en").text
    assert "incomplete report" not in clean
