"""Tests for the admin page: form login (SQLite sessions), CSRF, validation,
saving and the activity log."""

import importlib
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.auth import hash_password

EXAMPLE = Path(__file__).parent.parent / "requirements.example.yaml"
FIXTURE = Path(__file__).parent / "fixtures" / "olp_report.txt"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    config = tmp_path / "config"
    config.mkdir()
    shutil.copy(EXAMPLE, config / "requirements.yaml")
    (config / "admin_users.yaml").write_text(
        f"users:\n  terje: {hash_password('hemmelig123')}\n"
        f"  styremedlem: {hash_password('ogsåhemmelig')}\n"
    )
    monkeypatch.setenv("OSC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("OSC_UPLOADS_DIR", str(tmp_path / "data" / "uploads"))
    monkeypatch.setenv("OSC_REQUIREMENTS_PATH", str(config / "requirements.yaml"))
    monkeypatch.setenv("OSC_ADMIN_USERS_PATH", str(config / "admin_users.yaml"))

    import app.auth as auth_module
    from app import main

    importlib.reload(auth_module)
    importlib.reload(main)
    # The YAML users were imported at startup; give them a confirmed TOTP
    # secret so the existing tests are not stopped by the MFA requirement.
    for name in ("terje", "styremedlem"):
        main.database.set_totp_secret(name, TOTP_SECRET)
        main.database.confirm_totp(name, 0)
    # https base URL: the session cookie is Secure and would otherwise be
    # dropped by the cookie jar on plain http.
    return TestClient(main.app, base_url="https://testserver"), main


TOTP_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"


def _totp_code(secret: str = TOTP_SECRET, offset: int = 0) -> str:
    """The current code, or the one for a neighbouring 30 s step (offset ±1):
    a code is accepted once, so a second login in the same step uses the next."""
    import time

    import pyotp

    return pyotp.TOTP(secret).at(int(time.time() // 30 + offset) * 30)


def _login(c, username: str, password: str, *, code: str | None = None, **kwargs):
    """Password step, then (when the password was right) the TOTP step. Returns
    the final response of the step that was reached, redirects not followed."""
    response = c.post(
        "/admin/login", data={"username": username, "password": password},
        follow_redirects=False, **kwargs,
    )
    if response.status_code != 303 or "/admin/login/code" not in response.headers.get("location", ""):
        return response
    for offset in (0, 1):
        step = c.post("/admin/login/code", data={"code": code or _totp_code(offset=offset), "next": "/admin"},
                      follow_redirects=False)
        if step.status_code == 303 or code is not None:
            return step
    return step


def _csrf(page_html: str) -> str:
    import re

    return re.search(r'name="csrf" value="([^"]+)"', page_html).group(1)


def _updates(main):
    return [e for e in main.database.audit_entries() if e["action"] == "requirements_update"]


def test_admin_requires_login(client):
    c, _ = client
    response = c.get("/admin", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/admin/login?next=/admin"
    assert c.get("/admin/login").status_code == 200

    for user, pw in [("terje", "feilpassord"), ("finnesikke", "x")]:
        response = _login(c, user, pw)
        assert response.status_code == 401
        assert "Invalid username or password" in response.text
        assert "osc_admin" not in response.cookies
    assert c.get("/admin", follow_redirects=False).status_code == 303


def test_login_sets_cookie_and_page_renders_for_both_users(client):
    c, main = client
    for user, pw in [("terje", "hemmelig123"), ("styremedlem", "ogsåhemmelig")]:
        response = c.post("/admin/login", data={"username": user, "password": pw},
                          follow_redirects=False, headers={"CF-Connecting-IP": "203.0.113.9"})
        assert response.status_code == 303 and response.headers["location"] == "/admin/login/code?next=/admin"
        cookie = response.headers["set-cookie"]
        assert "osc_admin=" in cookie
        assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie.replace("Lax", "lax")
        assert "Path=/admin" in cookie
        assert c.get("/admin", follow_redirects=False).headers["location"].startswith("/admin/login/code")  # code still owed
        step = c.post("/admin/login/code", data={"code": _totp_code(), "next": "/admin"}, follow_redirects=False,
                      headers={"CF-Connecting-IP": "203.0.113.9"})
        assert step.status_code == 303 and step.headers["location"] == "/admin"

        page = c.get("/admin")
        assert page.status_code == 200
        assert user in page.text
        assert 'name="csrf"' in page.text
        assert "target_profile" in c.get("/admin/requirements").text  # the YAML content is shown

        # A logged-in user is sent straight from the login form to /admin
        assert c.get("/admin/login", follow_redirects=False).headers["location"] == "/admin"

        logins = [e for e in main.database.audit_entries() if e["action"] == "login"]
        assert logins[0]["username"] == user and logins[0]["ip"] == "203.0.113.9"
        c.cookies.clear()


def test_next_parameter_only_allows_admin_paths(client):
    c, _ = client
    assert c.get("/admin/login?next=https://evil.example/", follow_redirects=False).status_code == 200
    response = c.post(
        "/admin/login",
        data={"username": "terje", "password": "hemmelig123", "next": "https://evil.example/"},
        follow_redirects=False,
    )
    assert response.headers["location"] == "/admin/login/code?next=/admin"
    c.cookies.clear()
    response = c.post(
        "/admin/login",
        data={"username": "terje", "password": "hemmelig123", "next": "/admin?x=1"},
        follow_redirects=False,
    )
    assert response.headers["location"] == "/admin/login/code?next=/admin%3Fx%3D1"
    step = c.post("/admin/login/code", data={"code": _totp_code(offset=1), "next": "https://evil.example/"}, follow_redirects=False)
    assert step.headers["location"] == "/admin"  # the code form sanitises next too


def test_logout_invalidates_session(client):
    c, main = client
    _login(c, "terje", "hemmelig123")
    csrf = _csrf(c.get("/admin").text)
    response = c.post("/admin/logout", data={"csrf": csrf}, follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/admin/login"
    assert c.get("/admin", follow_redirects=False).status_code == 303
    assert [e["action"] for e in main.database.audit_entries()][:2] == ["logout", "login"]


def test_session_expires_when_idle(client):
    c, main = client
    _login(c, "terje", "hemmelig123")
    assert c.get("/admin").status_code == 200
    import sqlite3

    conn = sqlite3.connect(main.database.path)
    conn.execute("UPDATE admin_sessions SET last_seen_at = last_seen_at - ?", (9 * 3600,))
    conn.commit()
    assert c.get("/admin", follow_redirects=False).status_code == 303
    assert conn.execute("SELECT COUNT(*) FROM admin_sessions").fetchone()[0] == 0


def test_save_requires_csrf_token_and_same_site(client):
    c, main = client
    original = main.REQUIREMENTS_PATH.read_text()
    _login(c, "terje", "hemmelig123")
    new_text = original.replace('version: "2026-09-15"', 'version: "csrf-test"')

    # No token: what a cross-site form post would look like if the cookie leaked
    response = c.post("/admin/save", data={"yaml_text": new_text})
    assert response.status_code == 403
    # Wrong token
    response = c.post("/admin/save", data={"yaml_text": new_text, "csrf": "nope"})
    assert response.status_code == 403
    # Right token but the browser says the request came from another site
    csrf = _csrf(c.get("/admin").text)
    response = c.post(
        "/admin/save", data={"yaml_text": new_text, "csrf": csrf},
        headers={"Sec-Fetch-Site": "cross-site"},
    )
    assert response.status_code == 403
    assert main.REQUIREMENTS_PATH.read_text() == original
    assert _updates(main) == []

    # Same-site with the right token works
    response = c.post(
        "/admin/save", data={"yaml_text": new_text, "csrf": csrf},
        headers={"Sec-Fetch-Site": "same-origin"},
    )
    assert response.status_code == 200
    assert 'version: "csrf-test"' in main.REQUIREMENTS_PATH.read_text()


def test_save_rejects_invalid_yaml_without_writing(client):
    c, main = client
    original = main.REQUIREMENTS_PATH.read_text()
    _login(c, "terje", "hemmelig123")
    csrf = _csrf(c.get("/admin").text)
    response = c.post("/admin/save", data={"yaml_text": "dette er: [ikke gyldig", "csrf": csrf})
    assert response.status_code == 422
    assert "validation error" in response.text
    assert main.REQUIREMENTS_PATH.read_text() == original
    assert _updates(main) == []

    # Valid YAML but invalid structure (missing target_profile level)
    response = c.post(
        "/admin/save",
        data={"yaml_text": "version: x\nprofiles: ['2.1']\ntarget_profile: '2.1'\nmodules: []\n", "csrf": csrf},
    )
    assert response.status_code == 422
    assert main.REQUIREMENTS_PATH.read_text() == original


def test_save_writes_and_audits_with_user_ip_and_diff(client):
    c, main = client
    new_text = main.REQUIREMENTS_PATH.read_text().replace(
        'version: "2026-09-15"', 'version: "2026-09-official"'
    )
    _login(c, "styremedlem", "ogsåhemmelig")
    csrf = _csrf(c.get("/admin").text)
    response = c.post(
        "/admin/save",
        headers={"CF-Connecting-IP": "203.0.113.7"},
        data={"yaml_text": new_text, "csrf": csrf},
    )
    assert response.status_code == 200
    assert "Saved" in response.text
    assert "marlin_modules:" in main.REQUIREMENTS_PATH.read_text() and "HYDRA" in main.REQUIREMENTS_PATH.read_text()  # form save keeps the Marlin package
    assert 'version: "2026-09-official"' in main.REQUIREMENTS_PATH.read_text()

    entries = _updates(main)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["username"] == "styremedlem"
    assert entry["ip"] == "203.0.113.7"
    assert '-version: "2026-09-15"' in entry["detail"]
    assert '+version: "2026-09-official"' in entry["detail"]

    # The analysis uses the new requirements version immediately
    result = c.post("/analyze", files={"report": ("r.txt", FIXTURE.read_bytes(), "text/plain")}, data={"consent": "yes"})
    assert "2026-09-official" in result.text


def test_form_save_builds_valid_yaml_and_audits(client):
    c, main = client
    _login(c, "terje", "hemmelig123")
    form = {
        "csrf": _csrf(c.get("/admin").text),
        "version": "2026-09-form",
        "profiles": "2.0, 2.1",
        "target_profile": "2.1",
        "mod-0-id": "VCU",
        "mod-0-label": "Vehicle Control Unit",
        "mod-0-match": "VCU",
        "mod-0-extract": r"VCU\d{3}0*(\d+)$",
        "mod-0-level-2.0": "21",
        "mod-0-level-2.1": "23",
        "mod-0-critical": "yes",
        "mod-7-id": "BMS",  # non-contiguous index (the JS uses random ones)
        "mod-7-label": "Battery Management System",
        "mod-7-match": "BMS",
        "mod-7-extract": r"BMSN\d{3}0*(\d+)$",
        "mod-7-level-2.1": "21",
    }
    response = c.post("/admin/save-form", data=form)
    assert response.status_code == 200, response.text
    assert "Saved" in response.text

    saved = main.REQUIREMENTS_PATH.read_text()
    assert "2026-09-form" in saved
    from app.rules import load_requirements

    parsed = load_requirements(main.REQUIREMENTS_PATH)
    assert [m.id for m in parsed.modules] == ["VCU", "BMS"]
    assert parsed.modules[0].critical is True
    assert parsed.modules[1].critical is False  # checkbox not submitted
    assert parsed.modules[1].levels == {"2.1": 21}
    assert _updates(main)[0]["action"] == "requirements_update"


def test_form_save_rejects_bad_level(client):
    c, main = client
    original = main.REQUIREMENTS_PATH.read_text()
    _login(c, "terje", "hemmelig123")
    form = {
        "csrf": _csrf(c.get("/admin").text),
        "version": "x", "profiles": "2.1", "target_profile": "2.1",
        "mod-0-id": "VCU", "mod-0-level-2.1": "ikke-tall",
    }
    response = c.post("/admin/save-form", data=form)
    assert response.status_code == 422
    assert main.REQUIREMENTS_PATH.read_text() == original


def test_form_roundtrip_from_rendered_html(client):
    """Regression: render the admin page and post the form back UNCHANGED. The form
    regenerates the YAML (comments are dropped), so we require that the save
    validates OK and that the content is semantically identical."""
    import html as html_module
    import re as re_module

    c, main = client
    _login(c, "terje", "hemmelig123")
    page = c.get("/admin/requirements").text
    form_html = re_module.search(
        r'<form method="post" action="/admin/save-form">(.*?)</form>', page, re_module.DOTALL
    ).group(1)
    fields: list[tuple[str, str]] = []
    for m in re_module.finditer(r"<input([^>]*)>", form_html):
        attrs = dict(re_module.findall(r'(\w+)="([^"]*)"', m.group(1)))
        if attrs.get("type") == "checkbox":
            if "checked" in m.group(1):
                fields.append((attrs["name"], attrs.get("value", "on")))
        elif "name" in attrs:
            fields.append((attrs["name"], html_module.unescape(attrs.get("value", ""))))

    # Field names must be unique (a loop.index0 bug caused collisions between rows)
    names = [n for n, _ in fields]
    assert len(names) == len(set(names)), f"colliding field names: {sorted(names)}"
    assert "csrf" in names

    from app.rules import load_requirements

    before = load_requirements(main.REQUIREMENTS_PATH)
    response = c.post("/admin/save-form", data=dict(fields))
    assert response.status_code == 200, response.text
    after = load_requirements(main.REQUIREMENTS_PATH)
    assert [m.id for m in after.modules] == [m.id for m in before.modules]
    assert {m.id: m.levels for m in after.modules} == {m.id: m.levels for m in before.modules}
    assert {m.id: m.extract for m in after.modules} == {m.id: m.extract for m in before.modules}
    assert after.target_profile == before.target_profile
    # variants/only_trims survive a form save (the form cannot edit them)
    assert {m.id: m.only_trims for m in after.modules} == {m.id: m.only_trims for m in before.modules}
    assert {m.id: [(v.name, v.pattern, v.levels) for v in m.variants] for m in after.modules} == {
        m.id: [(v.name, v.pattern, v.levels) for v in m.variants] for m in before.modules
    }
    assert {m.id: m.marlin_level for m in after.modules} == {m.id: m.marlin_level for m in before.modules}
    assert after.modules[-1].marlin_level == 24  # VCU keeps its Marlin marker through a form save


def test_lockout_on_failed_logins_per_ip_and_per_user(client):
    c, _ = client
    ip = {"CF-Connecting-IP": "198.51.100.9"}
    for _ in range(10):
        assert _login(c, "terje", "feil", headers=ip).status_code == 401
    # Same IP, right password -> locked out
    assert _login(c, "terje", "hemmelig123", headers=ip).status_code == 429
    # Other IP, same username -> also locked out (per-user lock)
    assert _login(c, "terje", "hemmelig123", headers={"CF-Connecting-IP": "198.51.100.10"}).status_code == 429
    # Other IP, other user -> fine
    assert _login(c, "styremedlem", "ogsåhemmelig", headers={"CF-Connecting-IP": "198.51.100.10"}).status_code == 303


def test_admin_page_flags_invalid_requirements_file(client):
    """A bad edit on the host must be visible to admins: error shown, YAML
    editor open, and the form editor hidden; saving a valid file recovers."""
    c, main = client
    good = main.REQUIREMENTS_PATH.read_text()
    _login(c, "terje", "hemmelig123")
    main.REQUIREMENTS_PATH.write_text("modules: [\n")
    page = c.get("/admin/requirements")
    assert page.status_code == 200
    assert "requirements file on disk is INVALID" in page.text
    assert 'action="/admin/save-form"' not in page.text  # form editor needs a valid file
    assert 'name="yaml_text"' in page.text
    assert c.get("/healthz").status_code == 503

    csrf = _csrf(page.text)
    response = c.post("/admin/save", data={"yaml_text": good, "csrf": csrf})
    assert response.status_code == 200 and "Saved" in response.text
    assert c.get("/healthz").status_code == 200


def test_admin_warns_when_profiles_deviate_from_the_texts(client):
    """The verdict texts hardcode 2.1/2.2; the engine is generic. Saving a
    file with other profile names must succeed but show a warning."""
    c, main = client
    _login(c, "terje", "hemmelig123")
    page = c.get("/admin/requirements").text
    assert "the wording shown to members will no longer match" not in page
    csrf = _csrf(page)
    new_text = main.REQUIREMENTS_PATH.read_text().replace('target_profile: "2.1"', 'target_profile: "2.2"')
    response = c.post("/admin/save", data={"yaml_text": new_text, "csrf": csrf})
    assert response.status_code == 200 and "Saved" in response.text
    assert "result-page texts (all 7 languages) are written for target profile 2.1" in response.text
    assert "This file has target 2.2 and highest 2.2" in response.text


def test_form_save_keeps_notes_and_admin_shows_them(client):
    c, main = client
    _login(c, "terje", "hemmelig123")
    page = c.get("/admin/requirements").text
    assert "Open points" in page  # notes rendered
    assert 'data-profiles="[&#34;2.0&#34;' in page  # profiles handed to app.js, no inline script
    form = {
        "csrf": _csrf(page),
        "version": "notes-test", "profiles": "2.0, 2.1, 2.2", "target_profile": "2.1",
        "mod-0-id": "VCU", "mod-0-match": "VCU", "mod-0-level-2.1": "21",
    }
    response = c.post("/admin/save-form", data=form)
    assert response.status_code == 200 and "Saved" in response.text
    from app.rules import load_requirements

    saved = load_requirements(main.REQUIREMENTS_PATH)
    assert "Open points" in saved.notes
    assert saved.modules[0].marlin_level == 24  # per-module extras still preserved too


def test_form_editor_shows_variant_levels_for_bms(client):
    """BMS has no module-level numbers (they live on the NMC/LFP variants);
    the form must show them instead of an empty-looking row."""
    c, main = client
    _login(c, "terje", "hemmelig123")
    page = c.get("/admin/requirements").text
    assert page.count("NMC 21 / LFP 15") == 3  # one per profile column
    assert 'name="mod-4-level-2.1" value=""' in page and 'placeholder="per variant"' in page
    # The roundtrip still saves without inventing a base level for BMS
    csrf = _csrf(page)
    import html as html_module
    import re as re_module

    form_html = re_module.search(r'<form method="post" action="/admin/save-form">(.*?)</form>', page, re_module.DOTALL).group(1)
    fields = {}
    for m in re_module.finditer(r"<input([^>]*)>", form_html):
        attrs = dict(re_module.findall(r'(\w+)="([^"]*)"', m.group(1)))
        if attrs.get("type") == "checkbox":
            if "checked" in m.group(1):
                fields[attrs["name"]] = attrs.get("value", "on")
        elif "name" in attrs:
            fields[attrs["name"]] = html_module.unescape(attrs.get("value", ""))
    fields["csrf"] = csrf
    assert c.post("/admin/save-form", data=fields).status_code == 200
    from app.rules import load_requirements

    bms = next(m for m in load_requirements(main.REQUIREMENTS_PATH).modules if m.id == "BMS")
    assert bms.levels == {} and [v.levels["2.1"] for v in bms.variants] == [21, 15]


# --- the vehicle register --------------------------------------------------

FIXTURES = Path(__file__).parent / "fixtures"


def _upload_car(c, name: str, vin_suffix: str, **overrides):
    text = (FIXTURES / name).read_text()
    lines = []
    for line in text.splitlines():
        if line.startswith("VIN: "):
            line = line[:-2] + vin_suffix
        lines.append(line)
    text = "\n".join(lines)
    for code, value in overrides.items():
        text = text.replace(code, value)
    return c.post(
        "/analyze", files={"report": ("r.txt", text.encode(), "text/plain")},
        data={"consent": "yes"}, headers={"CF-IPCountry": "SE"},
    )


def test_register_pages_and_exports_require_login(client):
    c, _ = client
    for path in ("/admin/fleet", "/admin/fleet/vehicles.csv", "/admin/fleet/readings.csv",
                 "/admin/fleet/VCF1ZBE20PG099999"):
        response = c.get(path, follow_redirects=False)
        assert response.status_code == 303 and response.headers["location"].startswith("/admin/login")


def test_register_lists_filters_and_exports_vehicles(client):
    c, main = client
    _upload_car(c, "olp_report_21_full.txt", "01")
    _upload_car(c, "olp_report_22_full.txt", "02")
    _upload_car(c, "olp_report_21_full.txt", "03", BCM395030="BCM395042", VCU039021="VCU039023")
    _upload_car(c, "olp_report_21_full.txt", "01")  # second upload of the first car
    _login(c, "terje", "hemmelig123")

    page = c.get("/admin/fleet").text
    assert page.count('href="/admin/fleet/VCF1ZBE20PG0999') == 3
    assert "Clean 2.1" in page and "Full 2.2" in page and "2.2 zebra" in page
    filtered = c.get("/admin/fleet?outcome=zebra_22").text
    assert filtered.count('href="/admin/fleet/VCF1ZBE20PG0999') == 1 and "VCF1ZBE20PG099903" in filtered
    searched = c.get("/admin/fleet?q=99902").text
    assert "VCF1ZBE20PG099902" in searched and "VCF1ZBE20PG099901" not in searched

    vehicles = c.get("/admin/fleet/vehicles.csv")
    assert vehicles.status_code == 200
    assert vehicles.headers["content-type"].startswith("text/csv")
    assert vehicles.text.startswith("﻿vin;trim;")
    rows = vehicles.text.lstrip("﻿").splitlines()
    assert len(rows) == 4  # header + three vehicles (latest upload each)
    first_car = next(r for r in rows if "VCF1ZBE20PG099901" in r)
    assert ";2;full_21;2.1;2.1;SE;" in first_car  # two uploads, clean 2.1
    assert first_car.endswith(";BCM395030;89324V040200990131;88211V040000420131;ECC395 24;BMSN39021;MCU5000019;MCU5000019;VCU039021")

    readings = c.get("/admin/fleet/readings.csv")
    assert readings.status_code == 200
    lines = readings.text.lstrip("﻿").splitlines()
    assert len(lines) == 1 + 3 * 37  # every ECU of every stored report (the identical re-upload was merged)
    assert lines[0].startswith("submission_id;vin;uploaded_at_utc;")
    assert any(";ESP;ESP - Electronic Stability Program;CHASSIS;ESP;89819V050101060131;" in line for line in lines)

    exports = [e for e in main.database.audit_entries() if e["action"] == "export"]
    assert {e["detail"] for e in exports} == {"vehicles.csv", "readings.csv"}


def test_vehicle_page_history_and_deletion(client):
    c, main = client
    _upload_car(c, "olp_report_21_full.txt", "05")
    _upload_car(c, "olp_report_21_full.txt", "05", BCM395030="BCM395042", VCU039021="VCU039023")
    _login(c, "terje", "hemmelig123")

    page = c.get("/admin/fleet/VCF1ZBE20PG099905")
    assert page.status_code == 200
    assert page.text.count('<td class="mono">2026-09-15</td>') == 2  # two uploads listed (requirements version cell)
    assert "2.2 zebra" in page.text and "Clean 2.1" in page.text
    assert "BCM395042" in page.text  # newest upload shown by default
    assert "FM298033S001K" in page.text  # the software version field, not only Supplier SW
    key = main.database.link_key_for("VCF1ZBE20PG099905")
    assert f"/vehicle/{key}" in page.text  # admins see the permanent link too
    assert c.get("/admin/fleet/VCF1ZBE20PG000000").status_code == 404
    assert c.get("/admin/fleet/not-a-vin").status_code == 404

    assert len(list(Path(main.UPLOADS_DIR).iterdir())) == 2
    csrf = _csrf(page.text)
    response = c.post("/admin/fleet/VCF1ZBE20PG099905/delete", data={"csrf": csrf},
                      headers={"Sec-Fetch-Site": "same-origin"}, follow_redirects=False)
    assert response.status_code == 303
    assert main.database.stats()["unique_vins"] == 0
    assert list(Path(main.UPLOADS_DIR).iterdir()) == []
    assert main.database.latest_report_by_key(key) is None  # the permanent link dies with the vehicle
    assert c.get("/admin/fleet/VCF1ZBE20PG099905").status_code == 404
    deletions = [e for e in main.database.audit_entries() if e["action"] == "vehicle_delete"]
    assert len(deletions) == 1 and "VCF1ZBE20PG099905" in deletions[0]["detail"]
    assert "2 removed from disk" in deletions[0]["detail"]

    # Deleting needs CSRF like every other admin POST
    assert c.post("/admin/fleet/VCF1ZBE20PG099905/delete", data={}).status_code == 403


def test_updated_vehicles_page_and_csv(client):
    """Admins see which vehicles moved between their first and latest upload,
    with the lifted modules, and can export the list."""
    c, _ = client
    _upload_car(c, "olp_report_21_full.txt", "07")
    _upload_car(c, "olp_report_22_full.txt", "07")
    _upload_car(c, "olp_report_21_full.txt", "08")
    _login(c, "terje", "hemmelig123")

    page = c.get("/admin/fleet/progress").text
    assert "VCF1ZBE20PG099907" in page and "VCF1ZBE20PG099908" not in page
    assert "▲ up" in page and "ESP 402→501" in page and "IBS 400→401" in page

    csv_text = c.get("/admin/fleet/progress.csv").text.lstrip("\ufeff")
    rows = csv_text.splitlines()
    assert rows[0].startswith("vin;uploads;first_upload_utc;first_outcome;last_upload_utc;last_outcome;direction")
    assert len(rows) == 2 and ";2;" in rows[1] and ";full_21;" in rows[1] and ";full_22;up;" in rows[1]
    assert "VCU 21>23" in rows[1]


def test_reevaluate_button_applies_the_current_requirements(client):
    c, main = client
    _upload_car(c, "olp_report_22_full.txt", "06")
    _login(c, "terje", "hemmelig123")
    assert main.database.stats()["outcomes"] == {"full_22": 1}

    # Raise the ECC 2.2 level far above the car's 25 through the YAML editor, then re-evaluate
    csrf = _csrf(c.get("/admin").text)
    stricter = main.REQUIREMENTS_PATH.read_text().replace(
        'levels: {"2.0": 19, "2.1": 24, "2.2": 25}', 'levels: {"2.0": 19, "2.1": 24, "2.2": 30}'
    )
    c.post("/admin/save", data={"yaml_text": stricter, "csrf": csrf}, headers={"Sec-Fetch-Site": "same-origin"})
    assert main.database.stats()["outcomes"] == {"full_22": 1}  # stored outcome unchanged so far

    response = c.post("/admin/reevaluate", data={"csrf": csrf}, headers={"Sec-Fetch-Site": "same-origin"})
    assert response.status_code == 200
    assert "Re-evaluated 1 stored report(s)" in response.text
    assert main.database.stats()["outcomes"] == {"zebra_22": 1}
    assert any(e["action"] == "reevaluate" for e in main.database.audit_entries())


def test_totp_setup_is_required_and_codes_are_single_use(client):
    """A user without MFA can only reach the profile page; setting up TOTP
    there unlocks the rest. A code is accepted once, wrong codes count towards
    the lockout, and a session waiting for its code cannot use admin pages."""
    import pyotp

    c, main = client
    main.database.set_totp_secret("styremedlem", None)  # no MFA yet
    response = c.post("/admin/login", data={"username": "styremedlem", "password": "ogsåhemmelig"}, follow_redirects=False)
    assert response.headers["location"] == "/admin/profile?setup=1"
    assert c.get("/admin", follow_redirects=False).headers["location"] == "/admin/profile?setup=1"
    assert c.get("/admin/fleet", follow_redirects=False).status_code == 303
    profile = c.get("/admin/profile")
    assert profile.status_code == 200 and "required for every account" in profile.text
    csrf = _csrf(profile.text)

    started = c.post("/admin/profile/totp/start", data={"csrf": csrf}, headers={"Sec-Fetch-Site": "same-origin"})
    assert "<svg" in started.text
    secret = main.database.get_user("styremedlem")["totp_secret"]
    assert secret in started.text and main.database.get_user("styremedlem")["totp_confirmed_at"] is None
    wrong = c.post("/admin/profile/totp/confirm", data={"csrf": csrf, "code": "000000"}, headers={"Sec-Fetch-Site": "same-origin"})
    assert wrong.status_code == 400 and "<svg" in wrong.text  # try again with the same secret
    ok = c.post("/admin/profile/totp/confirm", data={"csrf": csrf, "code": pyotp.TOTP(secret).now()}, headers={"Sec-Fetch-Site": "same-origin"})
    assert ok.status_code == 200 and "is set up" in ok.text
    assert c.get("/admin").status_code == 200  # unlocked
    assert any(e["action"] == "mfa_setup" for e in main.database.audit_entries())

    # Next login: password, then the code. The same code is not accepted twice.
    c.cookies.clear()
    c.post("/admin/login", data={"username": "styremedlem", "password": "ogsåhemmelig"}, follow_redirects=False)
    code = _totp_code(secret, offset=1)
    assert c.post("/admin/login/code", data={"code": code, "next": "/admin"}, follow_redirects=False).status_code == 303
    c.cookies.clear()
    c.post("/admin/login", data={"username": "styremedlem", "password": "ogsåhemmelig"}, follow_redirects=False)
    assert c.post("/admin/login/code", data={"code": code, "next": "/admin"}, follow_redirects=False).status_code == 401
    for _ in range(10):
        c.post("/admin/login/code", data={"code": "123456", "next": "/admin"}, follow_redirects=False)
    assert c.post("/admin/login/code", data={"code": _totp_code(secret), "next": "/admin"}, follow_redirects=False).status_code == 429


def test_readonly_role_sees_but_cannot_change(client):
    c, main = client
    main.database.set_role("styremedlem", "readonly")
    _login(c, "styremedlem", "ogsåhemmelig")
    page = c.get("/admin")
    assert page.status_code == 200 and "read-only" in page.text
    assert "Re-evaluate all" not in page.text and 'href="/admin/users"' not in page.text
    assert "Validate and save" not in c.get("/admin/requirements").text
    for path in ("/admin/requirements", "/admin/settings", "/admin/analytics", "/admin/log"):
        assert c.get(path).status_code == 200
    assert c.get("/admin/fleet").status_code == 200 and c.get("/admin/fleet/vehicles.csv").status_code == 200
    csrf = _csrf(page.text)
    headers = {"Sec-Fetch-Site": "same-origin"}
    assert c.post("/admin/save", data={"yaml_text": "x", "csrf": csrf}, headers=headers).status_code == 403
    assert c.post("/admin/reevaluate", data={"csrf": csrf}, headers=headers).status_code == 403
    assert c.get("/admin/users").status_code == 403
    assert c.post("/admin/users/create", data={"username": "x", "csrf": csrf}, headers=headers).status_code == 403
    assert c.post("/admin/fleet/VCF1ZBE20PG099905/delete", data={"csrf": csrf}, headers=headers).status_code == 403


def test_user_management_panel(client):
    """Full admins create users (password shown once), change roles, issue
    passwords, reset MFA, disable and delete, but never remove themselves or
    the last full admin."""
    c, main = client
    _login(c, "terje", "hemmelig123")
    page = c.get("/admin/users")
    assert page.status_code == 200 and "styremedlem" in page.text
    assert "Last login (UTC)" in page.text
    assert main.database.get_user("terje")["last_login_at"] is not None  # set when the code was accepted
    assert main.database.get_user("styremedlem")["last_login_at"] is None
    csrf = _csrf(page.text)
    headers = {"Sec-Fetch-Site": "same-origin"}

    created = c.post("/admin/users/create", data={"username": "jens", "role": "readonly", "csrf": csrf}, headers=headers)
    assert created.status_code == 200 and "User jens created" in created.text
    import re

    password = re.search(r'<code class="mono">([^<]+)</code>', created.text).group(1)
    assert c.post("/admin/users/create", data={"username": "jens", "role": "readonly", "csrf": csrf}, headers=headers).status_code == 400
    assert c.post("/admin/users/create", data={"username": "Bad Name!", "role": "readonly", "csrf": csrf}, headers=headers).status_code == 400

    # The new user logs in with the shown password and is sent to MFA setup
    other = TestClient(main.app, base_url="https://testserver")
    assert other.post("/admin/login", data={"username": "jens", "password": password}, follow_redirects=False).headers["location"] == "/admin/profile?setup=1"

    assert "is now admin" in c.post("/admin/users/jens/role", data={"role": "admin", "csrf": csrf}, headers=headers).text
    assert c.post("/admin/users/terje/role", data={"role": "readonly", "csrf": csrf}, headers=headers).status_code == 200  # jens is admin now
    main.database.set_role("terje", "admin")
    main.database.set_role("jens", "readonly")
    main.database.set_role("styremedlem", "readonly")
    assert "leave no full admin" in c.post("/admin/users/terje/role", data={"role": "readonly", "csrf": csrf}, headers=headers).text
    assert "cannot disable your own" in c.post("/admin/users/terje/disable", data={"csrf": csrf}, headers=headers).text
    assert "cannot delete your own" in c.post("/admin/users/terje/delete", data={"csrf": csrf}, headers=headers).text

    assert "Two-factor authentication for styremedlem was reset" in c.post("/admin/users/styremedlem/reset-mfa", data={"csrf": csrf}, headers=headers).text
    assert main.database.get_user("styremedlem")["totp_secret"] is None
    assert "New password for jens" in c.post("/admin/users/jens/password", data={"csrf": csrf}, headers=headers).text
    assert "jens is disabled" in c.post("/admin/users/jens/disable", data={"csrf": csrf}, headers=headers).text
    assert other.post("/admin/login", data={"username": "jens", "password": password}, follow_redirects=False).status_code == 401
    assert "jens is enabled" in c.post("/admin/users/jens/enable", data={"csrf": csrf}, headers=headers).text
    assert "jens is deleted" in c.post("/admin/users/jens/delete", data={"csrf": csrf}, headers=headers).text
    assert main.database.get_user("jens") is None
    assert c.post("/admin/users/nobody/delete", data={"csrf": csrf}, headers=headers).status_code == 404
    actions = {e["action"] for e in main.database.audit_entries(limit=100)}
    assert {"user_create", "user_role", "user_password", "user_mfa_reset", "user_disable", "user_enable", "user_delete", "users_import"} <= actions


def test_manage_users_cli(client, monkeypatch):
    import scripts.manage_users as cli

    _, main = client
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "cli-password-123")
    data_dir = str(Path(main.database.path).parent)
    cli.main(["--data-dir", data_dir, "add", "opsuser", "--role", "readonly"])
    user = main.database.get_user("opsuser")
    assert user and user["role"] == "readonly" and user["created_by"] == "cli"
    cli.main(["--data-dir", data_dir, "reset-mfa", "terje"])
    assert main.database.get_user("terje")["totp_secret"] is None
    cli.main(["--data-dir", data_dir, "set-role", "opsuser", "admin"])
    assert main.database.get_user("opsuser")["role"] == "admin"
    cli.main(["--data-dir", data_dir, "list"])


def _fake_passkey_verification(monkeypatch, main, credential_id="cred-one"):
    """WebAuthn cannot run in TestClient: replace the cryptographic checks
    with stubs that accept a credential whose id is `credential_id`."""
    def fake_register(*, credential, challenge, rp_id, origin):
        assert challenge and rp_id == "testserver" and origin == "https://testserver"
        assert credential["id"] == credential_id
        return credential_id, b"public-key-bytes", 0

    def fake_authenticate(*, credential, challenge, rp_id, origin, public_key, sign_count):
        assert challenge and rp_id == "testserver" and public_key == b"public-key-bytes"
        if credential.get("id") != credential_id:
            raise ValueError("bad signature")
        return sign_count + 1

    monkeypatch.setattr(main.passkeys, "verify_registration", fake_register)
    monkeypatch.setattr(main.passkeys, "verify_authentication", fake_authenticate)


def test_passkey_registration_second_factor_and_passwordless_login(client, monkeypatch):
    c, main = client
    _fake_passkey_verification(monkeypatch, main)
    _login(c, "terje", "hemmelig123")
    csrf = _csrf(c.get("/admin/profile").text)
    headers = {"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}

    # Registration: options carry the challenge and rp id; the stored challenge is consumed once
    options = c.post("/admin/profile/passkey/options", json={}, headers=headers)
    assert options.status_code == 200 and options.json()["rp"]["id"] == "testserver"
    assert options.json()["authenticatorSelection"]["residentKey"] == "required"
    assert c.post("/admin/profile/passkey/options", json={}, headers={"Sec-Fetch-Site": "same-origin"}).status_code == 403  # no CSRF header
    registered = c.post("/admin/profile/passkey/register", json={"credential": {"id": "cred-one"}, "name": "iPhone"}, headers=headers)
    assert registered.status_code == 200 and registered.json() == {"ok": True, "name": "iPhone"}
    assert c.post("/admin/profile/passkey/register", json={"credential": {"id": "cred-one"}}, headers=headers).status_code == 400  # challenge consumed
    profile = c.get("/admin/profile").text
    assert "iPhone" in profile and main.database.count_passkeys("terje") == 1
    assert '<td class="num">1</td>' in c.get("/admin/users").text  # passkey count in the user list

    # Second factor: password first, then the passkey instead of a code
    c.cookies.clear()
    assert c.post("/admin/login", data={"username": "terje", "password": "hemmelig123"}, follow_redirects=False).headers["location"].startswith("/admin/login/code")
    page = c.get("/admin/login/code").text
    assert 'id="passkey-login"' in page and 'name="code"' in page  # both factors offered
    opts = c.post("/admin/login/passkey/options", json={}, headers={"Sec-Fetch-Site": "same-origin"})
    assert opts.status_code == 200 and opts.json()["allowCredentials"][0]["id"] == "cred-one"
    bad = c.post("/admin/login/passkey/verify", json={"credential": {"id": "someone-else"}}, headers={"Sec-Fetch-Site": "same-origin"})
    assert bad.status_code == 401
    c.post("/admin/login/passkey/options", json={}, headers={"Sec-Fetch-Site": "same-origin"})  # fresh challenge
    good = c.post("/admin/login/passkey/verify", json={"credential": {"id": "cred-one"}, "next": "/admin/users"}, headers={"Sec-Fetch-Site": "same-origin"})
    assert good.status_code == 200 and good.json() == {"ok": True, "next": "/admin/users"}
    assert c.get("/admin").status_code == 200
    assert main.database.get_passkey("cred-one")["sign_count"] == 1

    # Passwordless: no session at all, the discoverable passkey identifies the user
    other = TestClient(main.app, base_url="https://testserver")
    opts = other.post("/admin/login/passkey/options", json={}, headers={"Sec-Fetch-Site": "same-origin"})
    assert opts.status_code == 200 and "osc_admin=" in opts.headers["set-cookie"] and not opts.json().get("allowCredentials")
    assert other.get("/admin", follow_redirects=False).status_code == 303  # still only pending
    result = other.post("/admin/login/passkey/verify", json={"credential": {"id": "cred-one"}}, headers={"Sec-Fetch-Site": "same-origin"})
    assert result.status_code == 200 and result.json()["next"] == "/admin"
    page = other.get("/admin")
    assert page.status_code == 200 and "terje" in page.text
    assert any(e["action"] == "login" and "passkey ok" in e["detail"] for e in main.database.audit_entries())

    # A passkey alone satisfies the MFA requirement for a user without TOTP
    main.database.set_totp_secret("terje", None)
    other.cookies.clear()
    assert other.post("/admin/login", data={"username": "terje", "password": "hemmelig123"}, follow_redirects=False).headers["location"].startswith("/admin/login/code")
    page = other.get("/admin/login/code").text
    assert 'id="passkey-login"' in page and 'name="code"' not in page
    # ...and the only second factor cannot be removed
    csrf2 = _csrf(c.get("/admin/profile").text)
    refused = c.post("/admin/profile/passkey/cred-one/delete", data={"csrf": csrf2}, headers={"Sec-Fetch-Site": "same-origin"})
    assert refused.status_code == 400 and "only second factor" in refused.text
    main.database.set_totp_secret("terje", TOTP_SECRET)
    main.database.confirm_totp("terje", 0)
    removed = c.post("/admin/profile/passkey/cred-one/delete", data={"csrf": csrf2}, headers={"Sec-Fetch-Site": "same-origin"})
    assert removed.status_code == 200 and main.database.count_passkeys("terje") == 0


def test_passkey_registration_unlocks_an_account_without_mfa(client, monkeypatch):
    c, main = client
    _fake_passkey_verification(monkeypatch, main, credential_id="cred-two")
    main.database.set_totp_secret("styremedlem", None)
    c.post("/admin/login", data={"username": "styremedlem", "password": "ogsåhemmelig"}, follow_redirects=False)
    csrf = _csrf(c.get("/admin/profile").text)
    headers = {"Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
    assert c.post("/admin/profile/passkey/options", json={}, headers=headers).status_code == 200
    assert c.post("/admin/profile/passkey/register", json={"credential": {"id": "cred-two"}, "name": "Key"}, headers=headers).status_code == 200
    assert c.get("/admin").status_code == 200  # setup requirement lifted
    assert main.database.get_user("styremedlem")["last_login_at"] is not None


def test_odd_reports_are_flagged_in_the_register(client):
    """A report with an unreadable required module or too few control units
    gets a warning flag, a filter, and a notice on the vehicle page."""
    c, _ = client
    _upload_car(c, "olp_report_21_full.txt", "11")
    _upload_car(c, "olp_report_21_full.txt", "12", BCM395030="BCM-weird")   # BCM not readable
    _login(c, "terje", "hemmelig123")
    page = c.get("/admin/fleet").text
    assert page.count('class="oddflag"') == 1 and "BCM not readable" in page
    flagged = c.get("/admin/fleet?anomalies=1").text
    assert "VCF1ZBE20PG099912" in flagged and "VCF1ZBE20PG099911" not in flagged
    vehicle = c.get("/admin/fleet/VCF1ZBE20PG099912").text
    assert "This report looks incomplete" in vehicle and "BCM could not be read" in vehicle
    assert "This report looks incomplete" not in c.get("/admin/fleet/VCF1ZBE20PG099911").text


def test_work_order_switch_in_admin(client, monkeypatch):
    """The work order PDF can be switched off in the admin console: the button
    disappears and the routes answer 404. Read-only admins see the state."""
    c, main = client
    assert main.database.flag("workorder_enabled")
    _upload_car(c, "olp_report_21_full.txt", "21")
    _login(c, "terje", "hemmelig123")
    page = c.get("/admin/settings").text
    assert 'name="workorder_enabled" value="1" checked' in page
    csrf = _csrf(page)
    saved = c.post("/admin/settings", data={"csrf": csrf}, headers={"Sec-Fetch-Site": "same-origin"})  # unchecked
    assert "Settings saved." in saved.text and not main.database.flag("workorder_enabled")
    key = main.database.link_key_for("VCF1ZBE20PG099921")
    assert "/workorder" not in c.get(f"/vehicle/{key}").text
    assert c.get(f"/vehicle/{key}/workorder").status_code == 404
    c.post("/admin/settings", data={"csrf": csrf, "workorder_enabled": "1"}, headers={"Sec-Fetch-Site": "same-origin"})
    assert main.database.flag("workorder_enabled") and f"/vehicle/{key}/workorder" in c.get(f"/vehicle/{key}").text
    assert any(e["action"] == "settings" and "workorder_enabled=off" in e["detail"] for e in main.database.audit_entries())
    # The service provider link is a setting too, validated as a URL
    bad = c.post("/admin/settings", data={"csrf": csrf, "workorder_enabled": "1", "service_partner_url": "not a url"}, headers={"Sec-Fetch-Site": "same-origin"})
    assert bad.status_code == 400
    c.post("/admin/settings", data={"csrf": csrf, "workorder_enabled": "1", "service_partner_url": "https://example.org/help"}, headers={"Sec-Fetch-Site": "same-origin"})
    assert main.database.get_setting("service_partner_url") == "https://example.org/help"
    assert 'href="https://example.org/help" target="_blank"' in c.get(f"/vehicle/{key}").text
    # The SMTP relay lives in the settings too; a test message goes through it
    from app import mail
    sent = []
    monkeypatch.setattr(mail, "send", lambda relay, to, subject, text, attachments=None: sent.append((relay, to, subject)))
    base = {"csrf": csrf, "workorder_enabled": "1", "result_mail_enabled": "1"}
    assert c.post("/admin/settings", data={**base, "smtp_host": "bad host!"}, headers={"Sec-Fetch-Site": "same-origin"}).status_code == 400
    assert c.post("/admin/settings", data={**base, "smtp_host": "relay.example", "smtp_port": "99999"}, headers={"Sec-Fetch-Site": "same-origin"}).status_code == 400
    assert c.post("/admin/settings", data={**base, "smtp_host": "relay.example", "mail_from": "<<nope>>"}, headers={"Sec-Fetch-Site": "same-origin"}).status_code == 400
    page = c.post("/admin/settings", data={**base, "smtp_host": "relay.example", "smtp_port": "2525", "mail_from": "Check <noreply@example.org>"},
                  headers={"Sec-Fetch-Site": "same-origin"}).text
    assert main.database.get_setting("smtp_host") == "relay.example" and main.database.get_setting("smtp_port") == "2525"
    assert 'action="/admin/settings/test-mail"' in page and 'name="email"' in c.get(f"/vehicle/{key}").text
    assert c.post("/admin/settings/test-mail", data={"csrf": csrf, "email": "nope"}, headers={"Sec-Fetch-Site": "same-origin"}).status_code == 400
    ok = c.post("/admin/settings/test-mail", data={"csrf": csrf, "email": "admin@example.org"}, headers={"Sec-Fetch-Site": "same-origin"})
    assert "Test e-mail sent" in ok.text and sent[-1][0] == mail.Relay("relay.example", 2525, "Check <noreply@example.org>") and sent[-1][1] == "admin@example.org"
    assert any(e["action"] == "settings" and "smtp_host=relay.example" in e["detail"] for e in main.database.audit_entries())
    c.post("/admin/settings", data={**base, "smtp_host": ""}, headers={"Sec-Fetch-Site": "same-origin"})  # empty host = off
    assert 'name="email"' not in c.get(f"/vehicle/{key}").text


def test_merge_duplicate_uploads_in_admin(client):
    """The clean-up merges consecutive identical uploads per vehicle into the
    latest one, keeps counts, deletes files, and leaves distinct reports."""
    from app.parser import parse_report
    from app.rules import evaluate, load_requirements

    c, main = client
    requirements = load_requirements(EXAMPLE)
    Path(main.UPLOADS_DIR).mkdir(parents=True, exist_ok=True)

    def stored(name, vin_suffix, when, fname, **overrides):
        report = parse_report((Path(__file__).parent / "fixtures" / name).read_bytes(), name)
        report.vin = report.vin[:-2] + vin_suffix
        for m in report.modules:
            if m.code in overrides:
                m.supplier_sw = overrides[m.code]
        (Path(main.UPLOADS_DIR) / fname).write_text("x")
        sid = main.database.store_submission(report, evaluate(report, requirements), "en", fname)
        with main.database._connect() as conn:
            conn.execute("UPDATE submissions SET uploaded_at = ? WHERE id = ?", (when, sid))

    stored("olp_report_21_full.txt", "31", "2026-09-01T10:00:00+00:00", "a.txt")
    stored("olp_report_21_full.txt", "31", "2026-09-02T10:00:00+00:00", "b.txt")
    stored("olp_report_21_full.txt", "31", "2026-09-03T10:00:00+00:00", "c.txt")
    stored("olp_report_21_full.txt", "31", "2026-09-04T10:00:00+00:00", "d.txt", BCM="BCM395042")  # changed
    stored("olp_report_21_full.txt", "31", "2026-09-05T10:00:00+00:00", "e.txt", BCM="BCM395042")  # same again
    stored("olp_report_21_full.txt", "32", "2026-09-05T11:00:00+00:00", "f.txt")

    _login(c, "terje", "hemmelig123")
    csrf = _csrf(c.get("/admin").text)
    response = c.post("/admin/merge-duplicates", data={"csrf": csrf}, headers={"Sec-Fetch-Site": "same-origin"})
    assert response.status_code == 200 and "Merged 3 duplicate upload(s)" in response.text and "3 file(s) removed" in response.text
    history = main.database.vehicle_history("VCF1ZBE20PG099931")
    assert [(h["stored_filename"], h["upload_count"]) for h in history] == [("e.txt", 2), ("c.txt", 3)]
    assert sorted(f.name for f in Path(main.UPLOADS_DIR).iterdir()) == ["c.txt", "e.txt", "f.txt"]
    assert main.database.stats()["total_submissions"] == 6
    assert '<td class="num">3</td>' in c.get("/admin/fleet/VCF1ZBE20PG099931").text  # "Times" column
    assert any(e["action"] == "merge_duplicates" for e in main.database.audit_entries())


def test_admin_analytics_and_log_pages(client):
    """The detail that left the public dashboard renders on /admin/analytics:
    uploads chart, movement, month-by-month status, every control unit and the
    usage count. The activity log has its own page."""
    c, _ = client
    _login(c, "terje", "hemmelig123")
    _upload_car(c, "olp_report.txt", "31")
    _upload_car(c, "olp_report.txt", "31", BCM395021="BCM395030")  # same car again, BCM lifted 21 -> 30
    page = c.get("/admin/analytics?lang=en").text
    assert "Uploads over time" in page and 'id="panel-month"' in page
    assert page.count('class="col"') >= 60 + 26 + 1
    assert "Movement in the fleet" in page and "From first to latest report" in page
    assert "Fleet status month by month" in page
    assert "Every control unit in the reports" in page and "GW500002" in page
    assert "What holds the split cars back" in page and "Usage statistics" in page
    log = c.get("/admin/log").text
    assert "Activity log" in log and 'class="extra auditentry"' in log and "(login)" in log


def test_marlin_cars_card_and_register_filter(client):
    """Analytics splits the Marlin cars into full 2.2 with the whole package
    versus the rest, names what the rest lack, and the register can filter to
    those cars. The package state is stored per car and survives re-evaluation."""
    c, main = client
    _login(c, "terje", "hemmelig123")
    _upload_car(c, "olp_report_marlin.txt", "41")                      # on Marlin, full 2.2, package complete
    _upload_car(c, "olp_report_marlin.txt", "42", PDU4000D02="PDU3999D02")  # package: PDU below Marlin level
    _upload_car(c, "olp_report_marlin.txt", "43", BCM395042="BCM395030")    # BCM at 2.1 level
    _upload_car(c, "olp_report.txt", "44")                             # a zebra, not on Marlin
    stats = main.database.stats(main._current_requirements().profiles, main._current_requirements().target_profile)["marlin"]
    assert (stats["cars"], stats["full_top"], stats["both"], stats["pkg_complete"], stats["pkg_known"]) == (3, 2, 1, 2, 3)
    assert stats["pkg_missing"] == [{"module_id": "PDU", "n": 1}] and [m["module_id"] for m in stats["below_top"]] == ["BCM"]
    page = c.get("/admin/analytics").text
    assert "Marlin cars" in page and "Marlin package modules missing" in page
    rows = main.database.fleet_vehicles(marlin_gap="2.2")
    assert sorted(v["vin"][-2:] for v in rows) == ["42", "43"]
    assert "VCF1ZBE20PG099941" not in c.get("/admin/fleet?marlin_gap=1").text
    assert "VCF1ZBE20PG099942" in c.get("/admin/fleet?marlin_gap=1").text
    main.database.reevaluate_all(main._current_requirements())
    assert main.database.stats(["2.0", "2.1", "2.2"], "2.1")["marlin"]["both"] == 1
