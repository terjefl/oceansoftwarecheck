"""Ocean Software Check: web portal for the Fisker Owners Association."""

from __future__ import annotations

import asyncio
import csv
import difflib
import hashlib
import hmac
import io
import logging
import mimetypes
import os
import re
import secrets
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

from fastapi import Depends, FastAPI, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import auth, mail, passkeys
from . import db as db_module
from .auth import LoginRequired, client_ip
from .config import env
from .i18n import LANGUAGE_NAMES, SUPPORTED, block, negotiate_language, translator
from .parser import MAX_REPORT_BYTES, ReportParseError, parse_report, parse_report_date
from .rules import (
    OUTCOMES,
    TRIM_NAMES,
    RequirementSet,
    RequirementsValidationError,
    evaluate,
    incompleteness,
    load_requirements,
    parse_requirements_text,
)

log = logging.getLogger("oceansoftwarecheck")
if not logging.getLogger().handlers:  # uvicorn configures its own loggers, not the root
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

BASE_DIR = Path(__file__).parent
DATA_DIR = Path(env("DATA_DIR", "./data"))
UPLOADS_DIR = Path(env("UPLOADS_DIR", "./data/uploads"))
REQUIREMENTS_PATH = Path(env("REQUIREMENTS_PATH", "./requirements.example.yaml"))

# The admin session cookie is marked Secure unless explicitly disabled (local
# dev over plain http). Behind the Cloudflare tunnel the origin only sees http,
# so this cannot be derived from the request.
COOKIE_SECURE = env("COOKIE_SECURE", "1").strip().lower() not in ("0", "false", "no", "")
# Absolute base for the permanent per-vehicle links shown on the result page
# and in the PDF. Empty = derive from the request (X-Forwarded-Proto + Host,
# which is what the Cloudflare tunnel provides).
PUBLIC_URL = env("PUBLIC_URL", "").strip().rstrip("/")
RATE_LIMIT_UPLOADS = 10       # per IP per window
RATE_LIMIT_WINDOW = 60        # seconds
# Heavy, CPU- and memory-bound work (pdfplumber parsing and WeasyPrint PDF
# rendering) is limited to a few jobs at a time. Without a cap, a burst of
# uploads or PDF downloads would fan out over the whole threadpool (40
# threads) and could push the container past its memory limit; with it,
# extra requests simply wait their turn. The event loop stays free, so pages
# and statistics remain responsive while the queue drains.
MAX_HEAVY_JOBS = int(env("MAX_HEAVY_JOBS", "4"))
_heavy_jobs = asyncio.Semaphore(MAX_HEAVY_JOBS)


async def _run_heavy(func, *args):
    """Run a CPU-bound function in the threadpool, at most MAX_HEAVY_JOBS at once."""
    async with _heavy_jobs:
        return await run_in_threadpool(func, *args)

# The result-page wording (verdict_ready_text, verdict_zebra_text, ready_22_note
# in all seven locales) is written for the Marlin world where "2.1" is the
# profile required for a direct update and "2.2" is the highest profile. The
# rule engine itself is generic, so /admin warns when the file deviates from
# these names: the texts would then no longer match what is being checked.
TEXT_TARGET_PROFILE = "2.1"
TEXT_TOP_PROFILE = "2.2"

# Parse-error details that are safe to show visitors; everything else (e.g.
# pdfplumber's internal exception text) is only logged.
_USER_VISIBLE_PARSE_DETAILS = {"too_many_pages"}

app = FastAPI(title="Ocean Software Check", docs_url=None, redoc_url=None)
mimetypes.add_type("font/woff2", ".woff2")  # slim images lack /etc/mime.types; StaticFiles would answer text/plain
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

# Cache busting: content hash of style.css and app.js in the URL, so Cloudflare/browsers
# never serve stale CSS or JS after a deploy.
STATIC_VERSION = hashlib.md5(
    (BASE_DIR / "static" / "style.css").read_bytes() + (BASE_DIR / "static" / "app.js").read_bytes()
).hexdigest()[:8]

db_module.migrate_database_name(DATA_DIR)  # marlin.sqlite3 -> oceansoftwarecheck.sqlite3 (rename 2026-09-16)
database = db_module.Database(DATA_DIR / db_module.DB_FILENAME)
database.seed_settings(mail.ENV_DEFAULTS)
# Bootstrap: the first start copies the YAML admin users into the database.
if database.import_users_if_empty(auth.load_users()):
    database.add_audit("system", "-", "users_import", "admin users imported from admin_users.yaml")

# NOTE: all of this state (rate limits, login lockout) is per process —
# the app must run as exactly one uvicorn worker/replica.
_upload_hits: dict[str, list[float]] = {}


def _rate_limited(ip: str) -> bool:
    now = time.time()
    # Drop expired hits for every IP so the dict cannot grow without bound
    for known_ip in list(_upload_hits):
        recent = [t for t in _upload_hits[known_ip] if t > now - RATE_LIMIT_WINDOW]
        if recent:
            _upload_hits[known_ip] = recent
        else:
            del _upload_hits[known_ip]
    hits = _upload_hits.setdefault(ip, [])
    if len(hits) >= RATE_LIMIT_UPLOADS:
        return True
    hits.append(now)
    return False


MAIL_LIMIT = 5                 # result e-mails per IP per window
_mail_hits: dict[str, list[float]] = {}


def _mail_rate_limited(ip: str) -> bool:
    now = time.time()
    for known_ip in list(_mail_hits):
        recent = [x for x in _mail_hits[known_ip] if x > now - RATE_LIMIT_WINDOW]
        if recent:
            _mail_hits[known_ip] = recent
        else:
            del _mail_hits[known_ip]
    hits = _mail_hits.setdefault(ip, [])
    if len(hits) >= MAIL_LIMIT:
        return True
    hits.append(now)
    return False


def _render(request: Request, template: str, context: dict, status_code: int = 200) -> Response:
    lang = negotiate_language(request)
    response = templates.TemplateResponse(
        request,
        template,
        {"lang": lang, "t": translator(lang), "languages": LANGUAGE_NAMES,
         "static_v": STATIC_VERSION, "steps": block(lang, "intro_steps"),
         "path": request.url.path,  # nav highlighting in base.html / _admin_nav.html
         "role": getattr(request.state, "role", ""), **context},
        status_code=status_code,
    )
    if request.query_params.get("lang") in SUPPORTED:
        response.set_cookie("lang", lang, max_age=365 * 24 * 3600, samesite="lax")
    return response


# Key for the daily usage hash: random, held only in memory, replaced at the
# UTC day rollover (and on every restart). Because the key is never stored, a
# hash in the database cannot be brute-forced back to an IP address — a plain
# sha256(day|ip) with a public salt could be reversed over the IPv4 space in
# under an hour. The cost is that a restart splits that day's unique-user count.
_usage_key: dict = {"day": "", "key": b""}


def _usage_ip_hash(request: Request) -> str:
    """Daily-rotating keyed hash of the client IP — counts unique users per day
    without storing anything that can be linked back to the IP."""
    day = datetime.now(UTC).strftime("%Y-%m-%d")
    if _usage_key["day"] != day:
        _usage_key["day"], _usage_key["key"] = day, secrets.token_bytes(32)
    return hmac.new(_usage_key["key"], client_ip(request).encode(), hashlib.sha256).hexdigest()[:16]


def _log_usage(request: Request, lang: str, outcome: str, consent: bool) -> None:
    browser_lang = request.headers.get("accept-language", "").split(",")[0].split(";")[0].strip()
    try:
        database.add_usage(
            country=request.headers.get("cf-ipcountry", "").upper(),
            ui_lang=lang,
            browser_lang=browser_lang[:16],
            outcome=outcome,
            consent=consent,
            ip_hash=_usage_ip_hash(request),
        )
    except Exception:
        log.exception("Could not record usage event")


# Last-known-good requirements. The file is re-read on every use so admin
# edits apply immediately; if it is ever invalid or missing (a bad edit on the
# host, a mount that disappeared), analyses keep using the last good set and
# /healthz turns 503 so the problem is visible instead of every upload
# failing with a bare 500.
_requirements_state: dict = {"set": None, "error": None}


def _current_requirements() -> RequirementSet | None:
    try:
        current = load_requirements(REQUIREMENTS_PATH)
    except (RequirementsValidationError, OSError) as exc:
        if _requirements_state["error"] != str(exc):
            log.error("Requirements file %s unusable: %s", REQUIREMENTS_PATH, exc)
        _requirements_state["error"] = str(exc)
        return _requirements_state["set"]
    _requirements_state["set"], _requirements_state["error"] = current, None
    return current


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return _render(request, "index.html",
                   {"error": None, "requirements": _current_requirements()})


@app.get("/healthz")
def healthz():
    _current_requirements()
    if _requirements_state["error"]:
        return JSONResponse(
            {"status": "degraded", "requirements": _requirements_state["error"]},
            status_code=503,
        )
    return {"status": "ok"}


# Content-Security-Policy: everything is served from this origin; the only
# inline pieces are the value-driven width styles on the stats bars (hence
# 'unsafe-inline' for styles). All JavaScript lives in /static so no inline
# scripts are allowed. Fonts and images are self-hosted under /static.
_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; "
    "frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
)


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("Content-Security-Policy", _CSP)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    return response


@app.middleware("http")
async def _reject_oversized_uploads(request: Request, call_next):
    """Refuse an oversized POST /analyze from the Content-Length alone, before
    the multipart body is read. Multipart framing adds a little on top of the
    file itself, hence the slack."""
    if request.method == "POST" and request.url.path == "/analyze":
        try:
            declared = int(request.headers.get("content-length", "0"))
        except ValueError:
            declared = 0
        if declared > MAX_REPORT_BYTES + 64 * 1024:
            t = translator(negotiate_language(request))
            return _render(request, "index.html",
                           {"error": t("error_too_large"), "requirements": _current_requirements()},
                           status_code=413)
    return await call_next(request)


@app.get("/analyze")
def analyze_get(request: Request):
    """The language picker (and bookmarks) can hit /analyze with GET — e.g. from
    the error page, which is rendered directly on the POST URL. Redirect to the
    front page with the language choice preserved instead of returning 405."""
    lang = request.query_params.get("lang")
    return RedirectResponse(f"/?lang={lang}" if lang in SUPPORTED else "/", status_code=303)


def _parse_and_evaluate(data: bytes, filename: str, requirements: RequirementSet):
    """CPU-bound part of an upload (pdfplumber + rule engine). Runs in the
    threadpool so a slow PDF never blocks the event loop for other visitors."""
    parsed = parse_report(data, filename)
    return parsed, evaluate(parsed, requirements)


def _render_pdf(html: str) -> bytes:
    """WeasyPrint rendering: heavy import deferred until the first PDF, and
    run through the heavy-job limiter like report parsing."""
    from weasyprint import HTML

    return HTML(string=html).write_pdf()


async def _read_upload(report: UploadFile) -> bytes | None:
    """Reads the upload in chunks; None if it exceeds MAX_REPORT_BYTES, so a
    large file never has to sit in memory in full before being rejected."""
    buffer = bytearray()
    while chunk := await report.read(1024 * 1024):
        buffer += chunk
        if len(buffer) > MAX_REPORT_BYTES:
            return None
    return bytes(buffer)


@app.post("/analyze")
async def analyze(request: Request, report: UploadFile):
    lang = negotiate_language(request)
    t = translator(lang)

    if _rate_limited(client_ip(request)):
        return _render(request, "index.html", {"error": t("error_rate_limited"), "requirements": _current_requirements()}, status_code=429)

    requirements = _current_requirements()
    if requirements is None:
        # Invalid/missing file and nothing good seen since startup
        return _render(request, "index.html", {"error": t("error_requirements_unavailable"), "requirements": None}, status_code=503)

    data = await _read_upload(report)
    if data is None:
        return _render(request, "index.html", {"error": t("error_too_large"), "requirements": requirements}, status_code=413)

    form = await request.form()
    if form.get("consent") != "yes":
        return _render(request, "index.html", {"error": t("error_consent_required"), "requirements": requirements}, status_code=422)

    try:
        parsed, evaluation = await _run_heavy(
            _parse_and_evaluate, data, report.filename or "", requirements
        )
    except ReportParseError as exc:
        _log_usage(request, lang, "parse_error", consent=False)
        log.info("Report rejected (%s): %s", exc.key, exc.detail or "-")
        reason = t(f"parse_{exc.key}")
        if exc.detail and exc.key in _USER_VISIBLE_PARSE_DETAILS:
            reason += f" ({exc.detail})"
        return _render(
            request, "index.html", {"error": t("error_parse", reason=reason), "requirements": requirements}, status_code=422
        )

    # A partial export or a hand-made file: refused, nothing stored, no link
    # key handed out (the register must not be changed by a few typed lines).
    incomplete = incompleteness(parsed, evaluation)
    if incomplete:
        _log_usage(request, lang, "incomplete", consent=False)
        log.info("Report refused as incomplete: %s", incomplete)
        return _render(request, "index.html", {"error": t("error_incomplete"), "requirements": requirements}, status_code=422)

    # An older OLP export than the car's current report (a wrong file picked
    # by mistake) is analysed but not stored: the vehicle page shows the
    # stored report with a note about the older file.
    newer = database.newer_report_date(parsed.vin, str(parsed.meta.get("report_date", "")))
    if newer:
        _log_usage(request, lang, "older_report", consent=True)
        older = str(parsed.meta.get("report_date", ""))[:16]
        return RedirectResponse(f"/vehicle/{database.link_key_for(parsed.vin)}?older={quote(older)}", status_code=303)

    # Storage is mandatory (association decision, Sep 2026): the file and the
    # full module list go into the vehicle register.
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    safe_ext = ".pdf" if data[:5] == b"%PDF-" else ".txt"
    # Microseconds + a random tail: two uploads of the same VIN within a second
    # must not overwrite each other.
    stored_filename = (
        f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}"
        f"_{re.sub(r'[^A-Z0-9]', '', parsed.vin.upper())}_{secrets.token_hex(3)}{safe_ext}"
    )
    stored_path = UPLOADS_DIR / stored_filename
    stored_path.write_bytes(data)
    try:
        _submission_id, replaced_file = database.store_upload(
            parsed, evaluation, lang, stored_filename,
            country=request.headers.get("cf-ipcountry", "").upper(),
        )
    except Exception:
        # No row, no file: an orphaned upload would otherwise sit in the
        # uploads directory with nobody able to find or delete it.
        stored_path.unlink(missing_ok=True)
        raise
    if replaced_file and replaced_file != stored_filename:
        # Same report as the vehicle's latest: the row was refreshed, the old file is redundant
        (UPLOADS_DIR / Path(replaced_file).name).unlink(missing_ok=True)

    _log_usage(request, lang, evaluation.verdict, consent=True)

    # POST-redirect-GET straight to the vehicle's permanent link: the result
    # page is a GET page, so switching language, reloading and bookmarking work.
    return RedirectResponse(f"/vehicle/{database.link_key_for(parsed.vin)}", status_code=303)


def _public_base(request: Request) -> str:
    if PUBLIC_URL:
        return PUBLIC_URL
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    return f"{scheme}://{request.headers.get('host', request.url.netloc)}"


def _permanent_url(request: Request, link_key: str) -> str:
    return f"{_public_base(request)}/vehicle/{link_key}"


def _rp_id(request: Request) -> str:
    """The WebAuthn relying-party id: the site's host name without port."""
    base = _public_base(request)
    return base.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]


def _has_mfa(user: dict) -> bool:
    """Any second factor set up: a confirmed TOTP secret or at least one passkey."""
    return (bool(user.get("totp_secret")) and bool(user.get("totp_confirmed_at"))) or \
        database.count_passkeys(user["username"]) > 0


def _same_origin_json(request: Request) -> None:
    """JSON endpoints called from app.js: the browser must say same-origin."""
    fetch_site = request.headers.get("sec-fetch-site", "")
    if fetch_site and fetch_site not in ("same-origin", "none"):
        raise HTTPException(status_code=403, detail="Cross-site request rejected.")


def _result_page(request: Request, report, evaluation, *, pdf_url: str, link_key: str,
                 uploaded_at: str = "", changes: dict | None = None, report_age_days: int | None = None,
                 older_report: dict | None = None) -> Response:
    response = _render(
        request,
        "result.html",
        {
            "report": report, "evaluation": evaluation, "pdf_url": pdf_url,
            "permanent_url": _permanent_url(request, link_key),
            "uploaded_at": uploaded_at, "changes": changes, "report_age_days": report_age_days,
            "older_report": older_report,
            "workorder_enabled": database.flag("workorder_enabled"),
            "service_url": database.get_setting("service_partner_url"),
            "mail_enabled": _relay().enabled and database.flag("result_mail_enabled"),
            "mail_status": request.query_params.get("mail", ""),
            "page_path": request.url.path,
            "workorder_url": pdf_url[:-len("/pdf")] + "/workorder" if pdf_url.endswith("/pdf") else pdf_url + "/workorder",
        },
    )
    response.headers["Cache-Control"] = "private, no-store"  # contains the VIN
    return response


async def _pdf_response(request: Request, report, evaluation) -> Response:
    lang = negotiate_language(request)
    html = templates.get_template("pdf.html").render(
        lang=lang,
        t=translator(lang),
        report=report,
        evaluation=evaluation,
        for_pdf=True,  # DejaVu has no emoji: the template uses coloured ✓/✗ instead
        service_url=database.get_setting("service_partner_url"),
        generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
    )
    pdf_bytes = await _run_heavy(_render_pdf, html)
    filename = f"ocean-software-check_{report.vin}.pdf"
    return Response(
        pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "private, no-store",
        },
    )


def _workorder_rows(evaluation) -> list[dict]:
    """Modules to update, in the recommended order: first everything below the
    target profile (2.1), then what is still below the top profile (2.2)."""
    target, top = evaluation.target_profile, evaluation.profiles[-1]
    rows, seen = [], set()
    for profile in (target, top):
        for r in evaluation.below(profile):
            if r.requirement.id in seen:
                continue
            seen.add(r.requirement.id)
            needed = r.levels.get(profile) if r.levels.get(profile) is not None else r.top_required
            rows.append({
                "code": r.requirement.id, "label": r.requirement.label, "version": r.version,
                "extracted": r.extracted, "status": r.status, "needed": needed, "profile": profile,
            })
    return rows


def _workorder_html(lang: str, report, evaluation) -> str:
    rows = _workorder_rows(evaluation)
    codes = {r["code"] for r in rows}
    html = templates.get_template("workorder.html").render(
        lang=lang, t=translator(lang), report=report, evaluation=evaluation, rows=rows,
        pair_note=bool({"ESP", "IBS"} & codes),
        marlin_rows=evaluation.marlin_below if evaluation.outcome == "marlin" else [],
        for_pdf=True, generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
    )
    return html


async def _workorder_response(request: Request, report, evaluation) -> Response:
    if not database.flag("workorder_enabled"):
        raise HTTPException(status_code=404, detail="The work order is switched off.")
    html = _workorder_html(negotiate_language(request), report, evaluation)
    pdf_bytes = await _run_heavy(_render_pdf, html)
    return Response(
        pdf_bytes, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="ocean-software-check_checklist_{report.vin}.pdf"',
                 "Cache-Control": "private, no-store"},
    )


def _unknown_vehicle_link(request: Request) -> Response:
    t = translator(negotiate_language(request))
    return _render(request, "index.html",
                   {"error": t("permanent_link_unknown"), "requirements": _current_requirements()},
                   status_code=404)


@app.get("/result/{token}", response_class=HTMLResponse)
@app.get("/pdf/{token}")
@app.get("/pdf/{token}/workorder")
def retired_result_link(request: Request, token: str):
    """The temporary 30-minute result links from before the permanent link
    existed: explain instead of silently bouncing to the front page."""
    t = translator(negotiate_language(request))
    return _render(request, "index.html",
                   {"error": t("result_expired"), "requirements": _current_requirements()},
                   status_code=410)


# --- permanent per-vehicle link ---------------------------------------------
# /vehicle/<key> always shows the vehicle's latest stored report, evaluated
# against the current requirements, so it survives restarts and requirement
# changes. The key is random (128 bits) and only shown to whoever uploaded, so
# the register cannot be enumerated through it.

_LINK_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")


def _vehicle_by_key(key: str):
    if not _LINK_KEY_RE.fullmatch(key):
        return None
    found = database.latest_report_by_key(key)
    if found is None:
        return None
    requirements = _current_requirements()
    if requirements is None:
        raise HTTPException(status_code=503, detail="Requirements unavailable.")
    report, submission = found
    return report, evaluate(report, requirements), submission


@app.get("/vehicle/{key}", response_class=HTMLResponse)
def vehicle_page(request: Request, key: str):
    found = _vehicle_by_key(key)
    if found is None:
        return _unknown_vehicle_link(request)
    report, evaluation, submission = found
    older = request.query_params.get("older", "")
    return _result_page(request, report, evaluation, pdf_url=f"/vehicle/{key}/pdf",
                        link_key=key, uploaded_at=submission["uploaded_at"][:16].replace("T", " "),
                        changes=database.changes_since_previous(report.vin, submission["id"]),
                        report_age_days=_report_age_days(submission),
                        older_report={"uploaded": older, "stored": submission["report_date"][:16]}
                        if _REPORT_DATE_PARAM_RE.fullmatch(older) else None)


_REPORT_DATE_PARAM_RE = re.compile(r"^\d{4}-\d{2}-\d{2}( \d{2}:\d{2})?$")


def _report_age_days(submission) -> int | None:
    """How old the car's current report is: from the OLP report date when it
    is readable and not in the future (a wrong laptop clock), else from the
    upload time. None when neither can be read."""
    now = datetime.now(UTC)
    taken = parse_report_date(submission["report_date"])
    if taken is None or taken > now + timedelta(days=1):
        try:
            taken = datetime.fromisoformat(submission["uploaded_at"])
        except ValueError:
            return None
    return (now - taken).days


@app.get("/vehicle/{key}/pdf")
async def vehicle_pdf(request: Request, key: str):
    found = _vehicle_by_key(key)
    if found is None:
        return _unknown_vehicle_link(request)
    report, evaluation, _submission = found
    return await _pdf_response(request, report, evaluation)


@app.get("/vehicle/{key}/workorder")
async def vehicle_workorder(request: Request, key: str):
    found = _vehicle_by_key(key)
    if found is None:
        return _unknown_vehicle_link(request)
    report, evaluation, _submission = found
    return await _workorder_response(request, report, evaluation)


def _relay() -> mail.Relay:
    return mail.relay_from_settings(database.get_setting)


async def _mail_result(request: Request, report, evaluation, *, link_key: str, back: str) -> Response:
    """'Send me this result': the permanent link and the PDF to an address the
    member types in. The address is used once and not stored; only the fact
    that a mail went out is logged (no address, no VIN)."""
    relay = _relay()
    if not (relay.enabled and database.flag("result_mail_enabled")):
        raise HTTPException(status_code=404, detail="E-mail is switched off.")
    fetch_site = request.headers.get("sec-fetch-site", "")
    if fetch_site and fetch_site not in ("same-origin", "none"):
        raise HTTPException(status_code=403, detail="Cross-site request rejected.")
    form = await request.form()
    address = str(form.get("email", "")).strip()
    if not mail.valid_address(address):
        return RedirectResponse(f"{back}?mail=invalid", status_code=303)
    if _mail_rate_limited(client_ip(request)):
        return RedirectResponse(f"{back}?mail=limit", status_code=303)
    lang = negotiate_language(request)
    t = translator(lang)
    url = _permanent_url(request, link_key)
    outcome = t("outcome_" + evaluation.outcome) if evaluation.outcome else ""
    subject = t("mail_subject", vin=report.vin)
    if evaluation.unread:
        outcome += " " + t("incomplete_suffix")
    body = t("mail_body", vin=report.vin, outcome=outcome, url=url, checklist="{checklist}")
    if evaluation.unread:
        body = t("incomplete_report_note", modules=", ".join(r.requirement.id for r in evaluation.unread)) + "\n\n" + body
    pdf_html = templates.get_template("pdf.html").render(
        lang=lang, t=t, report=report, evaluation=evaluation, for_pdf=True,
        service_url=database.get_setting("service_partner_url"),
        generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
    )
    pdf_bytes = await _run_heavy(_render_pdf, pdf_html)
    attachments = [(f"ocean-software-check_{report.vin}.pdf", pdf_bytes, "application/pdf")]
    if form.get("checklist") == "1" and database.flag("workorder_enabled"):
        checklist = await _run_heavy(_render_pdf, _workorder_html(lang, report, evaluation))
        attachments.append((f"ocean-software-check_checklist_{report.vin}.pdf", checklist, "application/pdf"))
        body = body.replace("{checklist}", t("mail_body_checklist"))
    body = body.replace("{checklist}", "")
    try:
        await run_in_threadpool(mail.send, relay, address, subject, body, attachments)
    except Exception as exc:
        log.warning("Result e-mail failed: %s", exc)
        return RedirectResponse(f"{back}?mail=failed", status_code=303)
    log.info("Result e-mail sent (lang %s)", lang)
    return RedirectResponse(f"{back}?mail=sent", status_code=303)


@app.post("/vehicle/{key}/email")
async def vehicle_email(request: Request, key: str):
    found = _vehicle_by_key(key)
    if found is None:
        return _unknown_vehicle_link(request)
    report, evaluation, _submission = found
    return await _mail_result(request, report, evaluation, link_key=key, back=f"/vehicle/{key}")


def _fleet_stats() -> dict:
    requirements = _current_requirements()
    return database.stats(
        profiles=list(requirements.profiles) if requirements else None,
        target=requirements.target_profile if requirements else None,
    )


@app.get("/stats", response_class=HTMLResponse)
def stats(request: Request):
    """Public dashboard: outcomes, level per critical module, trims and countries.
    The working-group detail lives on /admin/analytics."""
    return _render(request, "stats.html", {"stats": _fleet_stats(), "trim_names": TRIM_NAMES})


@app.get("/privacy", response_class=HTMLResponse)
def privacy(request: Request):
    lang = negotiate_language(request)
    return _render(request, "privacy.html", {"paragraphs": block(lang, "privacy_paragraphs")})


@app.get("/how-it-works", response_class=HTMLResponse)
def how_it_works(request: Request):
    lang = negotiate_language(request)
    return _render(request, "how.html", {"sections": block(lang, "how_sections")})


# --- Admin: form login (SQLite sessions), requirements editing, audit log ---

def _safe_next(value: str | None) -> str:
    """Only redirect back to admin pages on the same site after login."""
    if value and value.startswith("/admin") and not value.startswith("//"):
        return value
    return "/admin"


class MfaRequired(Exception):
    """The password was accepted but the TOTP code is still owed."""


class MfaSetupRequired(Exception):
    """Logged in, but MFA is not set up yet: only the profile page is open."""


# Paths a session that still has to set up MFA may use.
_SETUP_PATHS = ("/admin/profile", "/admin/logout")


def _session_or_login(request: Request) -> dict:
    session = database.get_session(
        request.cookies.get(auth.SESSION_COOKIE, ""),
        idle_seconds=auth.SESSION_IDLE_SECONDS,
        max_age_seconds=auth.SESSION_MAX_SECONDS,
    )
    if session is None:
        raise LoginRequired()
    return session


def require_admin(request: Request) -> str:
    """FastAPI dependency: username of the logged-in admin (any role), or a
    redirect to the login form, the TOTP code form, or the MFA setup page.
    Sets request.state.csrf and request.state.role."""
    session = _session_or_login(request)
    if session["mfa_pending"]:
        raise MfaRequired()
    user = auth.find_user(database, session["username"])
    if user is None or user.get("disabled"):
        raise LoginRequired()
    if session["mfa_setup_required"] and not request.url.path.startswith(_SETUP_PATHS):
        raise MfaSetupRequired()
    request.state.csrf = session["csrf_token"]
    request.state.role = user.get("role", "admin")
    request.state.username = session["username"]
    return session["username"]


def require_full_admin(request: Request, username: str = Depends(require_admin)) -> str:
    """Only the 'admin' role may change anything; 'readonly' sees everything."""
    if request.state.role != "admin":
        raise HTTPException(status_code=403, detail="Your account has read-only access. Ask a full admin to make this change.")
    return username


async def require_csrf(request: Request, username: str = Depends(require_admin)) -> str:
    """For state-changing admin POSTs: the browser must say the request is
    same-site (Sec-Fetch-Site, unforgeable by other sites) AND the form must
    carry the session's CSRF token. Cookies are SameSite=Lax as a third layer."""
    fetch_site = request.headers.get("sec-fetch-site", "")
    if fetch_site and fetch_site not in ("same-origin", "none"):
        raise HTTPException(status_code=403, detail="Cross-site request rejected.")
    form = await request.form()
    submitted = str(form.get("csrf", ""))
    if not submitted or not secrets.compare_digest(submitted, request.state.csrf):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token — reload the page and try again.")
    return username


async def require_csrf_admin(request: Request, username: str = Depends(require_csrf)) -> str:
    """CSRF-checked POST by a full admin."""
    if request.state.role != "admin":
        raise HTTPException(status_code=403, detail="Your account has read-only access. Ask a full admin to make this change.")
    return username


@app.exception_handler(LoginRequired)
def _login_redirect(request: Request, exc: LoginRequired):
    return RedirectResponse(
        f"/admin/login?next={quote(request.url.path, safe='/')}", status_code=303
    )


@app.exception_handler(MfaRequired)
def _mfa_redirect(request: Request, exc: MfaRequired):
    return RedirectResponse(
        f"/admin/login/code?next={quote(request.url.path, safe='/')}", status_code=303
    )


@app.exception_handler(MfaSetupRequired)
def _mfa_setup_redirect(request: Request, exc: MfaSetupRequired):
    return RedirectResponse("/admin/profile?setup=1", status_code=303)


def _render_login(request: Request, *, error: str = "", next_path: str = "/admin",
                  status_code: int = 200) -> Response:
    return _render(request, "admin_login.html",
                   {"error": error, "next": next_path}, status_code=status_code)


@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_form(request: Request):
    if database.get_session(
        request.cookies.get(auth.SESSION_COOKIE, ""),
        idle_seconds=auth.SESSION_IDLE_SECONDS, max_age_seconds=auth.SESSION_MAX_SECONDS,
    ):
        return RedirectResponse(_safe_next(request.query_params.get("next")), status_code=303)
    return _render_login(request, next_path=_safe_next(request.query_params.get("next")))


@app.post("/admin/login")
async def admin_login(request: Request):
    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    next_path = _safe_next(str(form.get("next", "")))
    ip = client_ip(request)

    if auth.is_locked_out(ip, username):
        return _render_login(
            request, error="Too many failed login attempts. Try again in 15 minutes.",
            next_path=next_path, status_code=429,
        )
    user = auth.find_user(database, username) if username else None
    # PBKDF2 is CPU-bound: keep it off the event loop
    if not username or not await run_in_threadpool(auth.authenticate, username, password, ip, user):
        return _render_login(
            request, error="Invalid username or password.", next_path=next_path, status_code=401
        )

    # MFA is required for every account: with a confirmed TOTP secret the code
    # comes next; without one, only the profile page (setup) is reachable.
    has_mfa = _has_mfa(user)
    token, _csrf = database.create_session(username, mfa_pending=has_mfa, mfa_setup_required=not has_mfa)
    database.add_audit(username, ip, "login", "password ok, TOTP code pending" if has_mfa else "password ok, MFA setup required")
    target = f"/admin/login/code?next={quote(next_path, safe='/')}" if has_mfa else "/admin/profile?setup=1"
    response = RedirectResponse(target, status_code=303)
    response.set_cookie(
        auth.SESSION_COOKIE, token, max_age=auth.SESSION_MAX_SECONDS, path="/admin",
        httponly=True, secure=COOKIE_SECURE, samesite="lax",
    )
    return response


def _pending_session(request: Request) -> dict:
    """The session of a user who has given the right password but not the code."""
    session = _session_or_login(request)
    if not session["mfa_pending"]:
        raise LoginRequired()
    return session


def _render_code(request: Request, session: dict, *, error: str = "", next_path: str = "/admin",
                 status_code: int = 200) -> Response:
    user = database.get_user(session["username"]) or {}
    return _render(request, "admin_login_code.html", {
        "error": error, "next": next_path,
        "has_totp": bool(user.get("totp_secret")) and bool(user.get("totp_confirmed_at")),
        "has_passkeys": database.count_passkeys(session["username"]) > 0,
    }, status_code=status_code)


@app.get("/admin/login/code", response_class=HTMLResponse)
def admin_login_code_form(request: Request):
    session = _pending_session(request)
    return _render_code(request, session, next_path=_safe_next(request.query_params.get("next")))


@app.post("/admin/login/code")
async def admin_login_code(request: Request):
    session = _pending_session(request)
    form = await request.form()
    code = str(form.get("code", ""))
    next_path = _safe_next(str(form.get("next", "")))
    ip = client_ip(request)
    username = session["username"]
    if auth.is_locked_out(ip, username):
        return _render_code(request, session, error="Too many failed attempts. Try again in 15 minutes.",
                            next_path=next_path, status_code=429)
    user = database.get_user(username)
    step = auth.verify_totp(user["totp_secret"], code) if user and user.get("totp_secret") else None
    if step is None or not database.use_totp_counter(username, step):
        auth.register_failure(ip, username)
        database.add_audit(username, ip, "login_code_failed", "")
        return _render_code(request, session, error="Wrong code. Codes are valid once and change every 30 seconds.",
                            next_path=next_path, status_code=401)
    database.session_mfa_done(request.cookies.get(auth.SESSION_COOKIE, ""))
    database.record_login(username)
    database.add_audit(username, ip, "login", "TOTP code ok")
    return RedirectResponse(next_path, status_code=303)


@app.post("/admin/login/passkey/options")
async def admin_login_passkey_options(request: Request):
    """Options for navigator.credentials.get. With a pending session (password
    given) the user's own passkeys are allowed; without one, an anonymous
    pending session is created and any discoverable passkey may answer."""
    _same_origin_json(request)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    session = database.get_session(token, idle_seconds=auth.SESSION_IDLE_SECONDS, max_age_seconds=auth.SESSION_MAX_SECONDS)
    response_cookie = None
    if session is None or not session["mfa_pending"]:
        token, _csrf = database.create_session("", mfa_pending=True)
        session = {"username": ""}
        response_cookie = token
    allowed = [p["credential_id"] for p in database.list_passkeys(session["username"])] if session["username"] else []
    options, challenge = passkeys.authentication_options(rp_id=_rp_id(request), allowed_ids=allowed)
    database.set_challenge(token, challenge)
    response = Response(options, media_type="application/json", headers={"Cache-Control": "no-store"})
    if response_cookie:
        response.set_cookie(auth.SESSION_COOKIE, response_cookie, max_age=database.MFA_PENDING_SECONDS, path="/admin",
                            httponly=True, secure=COOKIE_SECURE, samesite="lax")
    return response


@app.post("/admin/login/passkey/verify")
async def admin_login_passkey_verify(request: Request):
    _same_origin_json(request)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    session = database.get_session(token, idle_seconds=auth.SESSION_IDLE_SECONDS, max_age_seconds=auth.SESSION_MAX_SECONDS)
    if session is None or not session["mfa_pending"]:
        raise HTTPException(status_code=401, detail="Start the sign-in again.")
    ip = client_ip(request)
    try:
        body = passkeys.parse_body(await request.body())
        credential = body.get("credential") or {}
        credential_id = passkeys.credential_id_of(credential)
    except ValueError:
        raise HTTPException(status_code=400, detail="Malformed request.") from None
    challenge = database.pop_challenge(token)
    passkey = database.get_passkey(credential_id) if credential_id else None
    username = session["username"] or (passkey["username"] if passkey else "")
    if auth.is_locked_out(ip, username):
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again in 15 minutes.")
    user = database.get_user(username) if username else None
    ok = bool(challenge and passkey and user and not user.get("disabled")
              and (not session["username"] or passkey["username"] == session["username"]))
    if ok:
        try:
            new_count = passkeys.verify_authentication(
                credential=credential, challenge=challenge, rp_id=_rp_id(request), origin=_public_base(request),
                public_key=passkey["public_key"], sign_count=passkey["sign_count"],
            )
        except Exception as exc:  # any verification failure: invalid signature, wrong origin, ...
            log.info("Passkey verification failed for %s: %s", username, exc)
            ok = False
        else:
            database.update_passkey_sign_count(credential_id, new_count)
    if not ok:
        auth.register_failure(ip, username)
        database.add_audit(username or "-", ip, "login_passkey_failed", "")
        raise HTTPException(status_code=401, detail="The passkey was not accepted.")
    if session["username"]:
        database.session_mfa_done(token)
    else:
        # Passwordless: the anonymous pending session (10 min cookie) is
        # replaced by a fresh full session, so the token rotates on login.
        database.delete_session(token)
        token, _csrf = database.create_session(username)
    database.record_login(username)
    database.add_audit(username, ip, "login", f"passkey ok ({passkey['name']})")
    response = JSONResponse({"ok": True, "next": _safe_next(str(body.get("next", "")))})
    # The pending cookie carried MFA_PENDING_SECONDS; the signed-in session
    # gets the ordinary lifetime, otherwise the browser drops it after 10 min.
    response.set_cookie(
        auth.SESSION_COOKIE, token, max_age=auth.SESSION_MAX_SECONDS, path="/admin",
        httponly=True, secure=COOKIE_SECURE, samesite="lax",
    )
    return response


@app.post("/admin/logout")
async def admin_logout(request: Request, username: str = Depends(require_csrf)):
    database.delete_session(request.cookies.get(auth.SESSION_COOKIE, ""))
    database.add_audit(username, client_ip(request), "logout", "")
    response = RedirectResponse("/admin/login", status_code=303)
    response.delete_cookie(auth.SESSION_COOKIE, path="/admin")
    return response


def _admin_page(request: Request, template: str, username: str, *, message: str = "",
                error: str = "", status_code: int = 200, **context) -> Response:
    """Common wrapper for the admin pages (nav needs username, csrf and role)."""
    return _render(request, template,
                   {"username": username, "csrf": request.state.csrf, "message": message, "error": error, **context},
                   status_code=status_code)


def _render_admin(request: Request, username: str, *, message: str = "", error: str = "",
                  status_code: int = 200) -> Response:
    """Overview: the register tiles and the maintenance buttons."""
    return _admin_page(request, "admin.html", username, message=message, error=error,
                       status_code=status_code, fleet=_fleet_stats())


def _render_settings(request: Request, username: str, *, message: str = "", error: str = "",
                     status_code: int = 200) -> Response:
    return _admin_page(
        request, "admin_settings.html", username, message=message, error=error, status_code=status_code,
        settings={"workorder_enabled": database.flag("workorder_enabled"),
                  "result_mail_enabled": database.flag("result_mail_enabled"),
                  "mail_configured": _relay().enabled,
                  "smtp_host": database.get_setting("smtp_host"),
                  "smtp_port": database.get_setting("smtp_port"),
                  "mail_from": _relay().sender,
                  "service_partner_url": database.get_setting("service_partner_url")},
    )


def _render_requirements(request: Request, username: str, *, message: str = "",
                         error: str = "", yaml_text: str | None = None,
                         status_code: int = 200) -> Response:
    try:
        current_text = REQUIREMENTS_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        current_text = ""
        error = error or f"The requirements file cannot be read ({exc}). Analyses use the last valid version loaded, if any."
    try:
        requirements = parse_requirements_text(current_text)
    except RequirementsValidationError as exc:
        requirements = None  # show only the YAML editor if the file is invalid
        error = error or (
            f"The requirements file on disk is INVALID and analyses use the last valid "
            f"version loaded, if any. Fix and save it below. Error: {exc}"
        )
    profile_warning = ""
    if requirements is not None:
        top = requirements.profiles[-1] if requirements.profiles else ""
        if requirements.target_profile != TEXT_TARGET_PROFILE or top != TEXT_TOP_PROFILE:
            profile_warning = (
                f"The result-page texts (all 7 languages) are written for target profile "
                f"{TEXT_TARGET_PROFILE} and highest profile {TEXT_TOP_PROFILE}. This file has "
                f"target {requirements.target_profile} and highest {top}: the verdicts are "
                f"computed correctly, but the wording shown to members will no longer match. "
                f"Changing the profiles requires updating the texts in the source code "
                f"(app/locales/*.json: verdict_ready_text, verdict_zebra_text, ready_22_note)."
            )
    return _admin_page(
        request, "admin_requirements.html", username, message=message, error=error, status_code=status_code,
        profile_warning=profile_warning, requirements=requirements,
        yaml_text=yaml_text if yaml_text is not None else current_text,
    )


def _save_requirements(request: Request, username: str, new_text: str) -> Response:
    """Shared save logic for the form editor and the raw YAML editor."""
    old_text = REQUIREMENTS_PATH.read_text(encoding="utf-8")
    if new_text.strip() == old_text.strip():
        return _render_requirements(request, username, message="No changes to save.")

    try:
        parsed = parse_requirements_text(new_text)
    except RequirementsValidationError as exc:
        return _render_requirements(
            request, username, error=f"Not saved — validation error: {exc}",
            yaml_text=new_text, status_code=422,
        )

    diff = "\n".join(
        difflib.unified_diff(
            old_text.splitlines(), new_text.splitlines(),
            fromfile="requirements.yaml (before)", tofile="requirements.yaml (after)",
            lineterm="",
        )
    )[:20000]

    # Atomic replace within the same directory (which is why /config is mounted as a directory)
    tmp_path = REQUIREMENTS_PATH.with_suffix(".yaml.tmp")
    tmp_path.write_text(new_text, encoding="utf-8")
    os.replace(tmp_path, REQUIREMENTS_PATH)

    database.add_audit(username, client_ip(request), "requirements_update", diff)
    return _render_requirements(
        request, username,
        message=f"Saved. New requirements version: {parsed.version} "
                f"({len(parsed.modules)} modules, target {parsed.target_profile}).",
    )


@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request, username: str = Depends(require_admin)):
    return _render_admin(request, username)


@app.get("/admin/requirements", response_class=HTMLResponse)
def admin_requirements(request: Request, username: str = Depends(require_admin)):
    return _render_requirements(request, username)


@app.get("/admin/settings", response_class=HTMLResponse)
def admin_settings_page(request: Request, username: str = Depends(require_admin)):
    return _render_settings(request, username)


@app.get("/admin/analytics", response_class=HTMLResponse)
def admin_analytics(request: Request, username: str = Depends(require_admin)):
    progress = database.fleet_progress()
    progress.pop("vehicles", None)
    return _admin_page(
        request, "admin_analytics.html", username,
        stats=_fleet_stats(), trim_names=TRIM_NAMES, timeseries=database.uploads_over_time(),
        progress=progress, history=database.fleet_status_by_month(), usage=database.usage_stats(14),
    )


@app.get("/admin/log", response_class=HTMLResponse)
def admin_log(request: Request, username: str = Depends(require_admin)):
    return _admin_page(request, "admin_log.html", username, audit=database.audit_entries(200))


@app.post("/admin/save")
async def admin_save(request: Request, username: str = Depends(require_csrf_admin)):
    form = await request.form()
    new_text = str(form.get("yaml_text", "")).replace("\r\n", "\n")
    return _save_requirements(request, username, new_text)


@app.post("/admin/save-form")
async def admin_save_form(request: Request, username: str = Depends(require_csrf_admin)):
    form = await request.form()
    try:
        new_text = _form_to_yaml(form, username)
    except ValueError as exc:
        return _render_requirements(
            request, username, error=f"Not saved — {exc}", status_code=422
        )
    return _save_requirements(request, username, new_text)


def _form_to_yaml(form, username: str) -> str:
    """Builds requirements YAML from the admin form. Raises ValueError on obvious errors."""
    import yaml as yaml_module

    profiles = [p.strip() for p in str(form.get("profiles", "")).split(",") if p.strip()]
    if not profiles:
        raise ValueError("at least one profile must be specified.")

    modules = []
    indices = sorted(
        {m.group(1) for k in form if (m := re.match(r"mod-(\d+)-id$", k))},
        key=int,
    )
    for i in indices:
        module_id = str(form.get(f"mod-{i}-id", "")).strip()
        if not module_id:
            continue  # empty row
        levels = {}
        for profile in profiles:
            value = str(form.get(f"mod-{i}-level-{profile}", "")).strip()
            if value:
                try:
                    levels[profile] = int(value)
                except ValueError:
                    raise ValueError(
                        f"module {module_id}: level for {profile} must be an integer (got {value!r})."
                    ) from None
        module: dict = {
            "id": module_id,
            "label": str(form.get(f"mod-{i}-label", "")).strip() or module_id,
            "match": [s.strip() for s in str(form.get(f"mod-{i}-match", "")).split(",") if s.strip()]
            or [module_id],
            "levels": levels,
            "critical": "yes" in form.getlist(f"mod-{i}-critical"),
        }
        extract = str(form.get(f"mod-{i}-extract", "")).strip()
        if extract:
            module["extract"] = extract
        modules.append(module)

    # The form cannot edit `variants`/`only_trims`/`marlin_level`; carry them
    # over from the current file so a form save does not silently drop them.
    try:
        current_raw = yaml_module.safe_load(REQUIREMENTS_PATH.read_text(encoding="utf-8")) or {}
        if not isinstance(current_raw, dict):
            current_raw = {}
        preserved = {
            m["id"]: {k: m[k] for k in ("variants", "only_trims", "marlin_level") if k in m}
            for m in current_raw.get("modules", [])
            if isinstance(m, dict) and "id" in m
        }
    except (OSError, yaml_module.YAMLError):
        current_raw, preserved = {}, {}
    for module in modules:
        extras = preserved.get(module["id"], {})
        module.update(extras)
        # A variant-only module keeps empty base levels out of the file
        if not module["levels"] and extras.get("variants"):
            module.pop("levels")

    data = {
        "version": str(form.get("version", "")).strip(),
        "profiles": profiles,
        "target_profile": str(form.get("target_profile", "")).strip(),
    }
    # Free-text `notes` (sources, open points) are carried over untouched:
    # YAML comments do not survive a form save, this field does.
    if isinstance(current_raw.get("notes"), str) and current_raw["notes"].strip():
        data["notes"] = current_raw["notes"]
    data["modules"] = modules
    # `marlin_modules` (what the Marlin update installs) has no form fields either.
    if isinstance(current_raw.get("marlin_modules"), list) and current_raw["marlin_modules"]:
        data["marlin_modules"] = current_raw["marlin_modules"]
    header = (
        "# Marlin requirements: minimum levels per ECU and software profile.\n"
        "# NOTE: `variants`, `only_trims`, `marlin_level`, `marlin_modules` and `notes` are preserved from the\n"
        "# previous file (the form editor cannot change them — use the YAML editor for that).\n"
        f"# Generated by the admin form on Ocean Software Check (user: {username}).\n"
        "# Field documentation: requirements.example.yaml in the source repo\n"
        "# https://github.com/terjefl/oceansoftwarecheck\n\n"
    )
    return header + yaml_module.safe_dump(
        data, allow_unicode=True, sort_keys=False, default_flow_style=False, width=100
    )


# --- Admin: settings (feature switches) --------------------------------------

_SWITCHES = ("workorder_enabled", "result_mail_enabled")


@app.post("/admin/settings")
async def admin_settings(request: Request, username: str = Depends(require_csrf_admin)):
    form = await request.form()
    changed = []
    for key in _SWITCHES:
        value = "1" if form.get(key) == "1" else "0"
        if database.get_setting(key) != value:
            database.set_setting(key, value, username)
            changed.append(f"{key}={'on' if value == '1' else 'off'}")
    url = str(form.get("service_partner_url", "")).strip()
    if url and not re.fullmatch(r"https?://[^\s<>\"']+", url):
        return _render_settings(request, username, error="Service partner link: must start with http:// or https:// and contain no spaces.", status_code=400)
    if url and url != database.get_setting("service_partner_url"):
        database.set_setting("service_partner_url", url, username)
        changed.append(f"service_partner_url={url}")
    host = str(form.get("smtp_host", "")).strip()
    port = str(form.get("smtp_port", "")).strip() or "587"
    sender = str(form.get("mail_from", "")).strip()
    if not mail.valid_host(host):
        return _render_settings(request, username, error="SMTP relay: host name only (letters, digits, dots, dashes), or empty to switch e-mail off.", status_code=400)
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        return _render_settings(request, username, error="SMTP relay: the port must be a number between 1 and 65535.", status_code=400)
    if sender and not mail.valid_sender(sender):
        return _render_settings(request, username, error="Sender: use an address, or Name <address>.", status_code=400)
    for key, value in (("smtp_host", host), ("smtp_port", port), ("mail_from", sender)):
        if "smtp_host" in form and database.get_setting(key) != value:
            database.set_setting(key, value, username)
            changed.append(f"{key}={value or '(empty)'}")
    if changed:
        database.add_audit(username, client_ip(request), "settings", ", ".join(changed))
    return _render_settings(request, username, message="Settings saved." if changed else "No settings changed.")


@app.post("/admin/settings/test-mail")
async def admin_test_mail(request: Request, username: str = Depends(require_csrf_admin)):
    """Sends a short test message through the configured relay to the address typed in."""
    form = await request.form()
    address = str(form.get("email", "")).strip()
    relay = _relay()
    if not relay.enabled:
        return _render_settings(request, username, error="No SMTP relay configured.", status_code=400)
    if not mail.valid_address(address):
        return _render_settings(request, username, error="Test e-mail: that does not look like an address.", status_code=400)
    try:
        await run_in_threadpool(mail.send, relay, address, "Ocean Software Check: test message",
                                f"This is a test message from the admin console, requested by {username}.\n"
                                f"Relay: {relay.host}:{relay.port}, sender: {relay.sender}.")
    except Exception as exc:
        return _render_settings(request, username, error=f"Test e-mail failed: {exc}", status_code=400)
    database.add_audit(username, client_ip(request), "settings", "test e-mail sent")
    return _render_settings(request, username, message="Test e-mail sent. Check the inbox (and the spam folder).")


# --- Admin: own profile (password, MFA) -------------------------------------

def _render_profile(request: Request, username: str, *, message: str = "", error: str = "",
                    setup: dict | None = None, status_code: int = 200) -> Response:
    user = database.get_user(username) or {}
    session = _session_or_login(request)
    return _render(request, "admin_profile.html", {
        "username": username, "csrf": request.state.csrf, "user": user,
        "has_mfa": bool(user.get("totp_secret")) and bool(user.get("totp_confirmed_at")),
        "passkeys": database.list_passkeys(username),
        "setup_required": session["mfa_setup_required"],
        "setup": setup, "message": message, "error": error,
    }, status_code=status_code)


def _csrf_header(request: Request) -> None:
    submitted = request.headers.get("x-csrf-token", "")
    if not submitted or not secrets.compare_digest(submitted, request.state.csrf):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token.")


@app.post("/admin/profile/passkey/options")
async def admin_profile_passkey_options(request: Request, username: str = Depends(require_admin)):
    _same_origin_json(request)
    _csrf_header(request)
    existing = [p["credential_id"] for p in database.list_passkeys(username)]
    options, challenge = passkeys.registration_options(rp_id=_rp_id(request), username=username, existing_ids=existing)
    database.set_challenge(request.cookies.get(auth.SESSION_COOKIE, ""), challenge)
    return Response(options, media_type="application/json", headers={"Cache-Control": "no-store"})


@app.post("/admin/profile/passkey/register")
async def admin_profile_passkey_register(request: Request, username: str = Depends(require_admin)):
    _same_origin_json(request)
    _csrf_header(request)
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    try:
        body = passkeys.parse_body(await request.body())
        credential = body.get("credential") or {}
    except ValueError:
        raise HTTPException(status_code=400, detail="Malformed request.") from None
    challenge = database.pop_challenge(token)
    if not challenge:
        raise HTTPException(status_code=400, detail="No registration in progress. Try again.")
    name = str(body.get("name", "")).strip()[:60] or "Passkey"
    try:
        credential_id, public_key, sign_count = passkeys.verify_registration(
            credential=credential, challenge=challenge, rp_id=_rp_id(request), origin=_public_base(request),
        )
    except Exception as exc:
        log.info("Passkey registration failed for %s: %s", username, exc)
        raise HTTPException(status_code=400, detail="The passkey could not be verified. Try again.") from None
    if database.get_passkey(credential_id):
        raise HTTPException(status_code=400, detail="That passkey is already registered.")
    database.add_passkey(username, credential_id, public_key, sign_count, name)
    session = _session_or_login(request)
    if session["mfa_setup_required"]:
        database.session_setup_done(token)
        database.record_login(username)
    database.add_audit(username, client_ip(request), "passkey_add", name)
    return JSONResponse({"ok": True, "name": name})


@app.post("/admin/profile/passkey/{credential_id}/delete")
async def admin_profile_passkey_delete(request: Request, credential_id: str, username: str = Depends(require_csrf)):
    user = database.get_user(username) or {}
    has_totp = bool(user.get("totp_secret")) and bool(user.get("totp_confirmed_at"))
    if not has_totp and database.count_passkeys(username) <= 1:
        return _render_profile(request, username, error="This is your only second factor. Set up an authenticator app or add another passkey first.", status_code=400)
    if not database.delete_passkey(username, credential_id):
        raise HTTPException(status_code=404, detail="No such passkey.")
    database.add_audit(username, client_ip(request), "passkey_delete", credential_id[:12])
    return _render_profile(request, username, message="Passkey removed.")


@app.get("/admin/profile", response_class=HTMLResponse)
def admin_profile(request: Request, username: str = Depends(require_admin)):
    if username and database.get_user(username) is None:
        # A YAML-only (rescue) user: create the database record so MFA can be stored
        yaml_user = auth.find_user(database, username)
        if yaml_user:
            database.create_user(username, yaml_user["password_hash"], "admin", "yaml")
    return _render_profile(request, username)


@app.post("/admin/profile/password")
async def admin_profile_password(request: Request, username: str = Depends(require_csrf)):
    form = await request.form()
    current, new, repeat = str(form.get("current", "")), str(form.get("new", "")), str(form.get("repeat", ""))
    user = database.get_user(username)
    if not user or not auth.verify_password(current, user["password_hash"]):
        return _render_profile(request, username, error="The current password is wrong.", status_code=400)
    if len(new) < 12:
        return _render_profile(request, username, error="The new password must have at least 12 characters.", status_code=400)
    if new != repeat:
        return _render_profile(request, username, error="The two new passwords differ.", status_code=400)
    database.set_password(username, await run_in_threadpool(auth.hash_password, new))
    database.add_audit(username, client_ip(request), "password_change", "own password")
    return _render_profile(request, username, message="Password changed.")


@app.post("/admin/profile/totp/start")
async def admin_profile_totp_start(request: Request, username: str = Depends(require_csrf)):
    """Generates a new secret and shows the QR code; nothing counts until a
    code is confirmed. Replacing an existing device needs the current code."""
    form = await request.form()
    user = database.get_user(username)
    if user and user.get("totp_confirmed_at"):
        step = auth.verify_totp(user["totp_secret"], str(form.get("code", "")))
        if step is None or not database.use_totp_counter(username, step):
            return _render_profile(request, username, error="Enter a valid code from your current device to replace it.", status_code=400)
    secret = auth.new_totp_secret()
    database.set_totp_secret(username, secret)
    uri = auth.totp_uri(secret, username)
    return _render_profile(request, username, setup={"secret": secret, "svg": auth.totp_qr_svg(uri)})


@app.post("/admin/profile/totp/confirm")
async def admin_profile_totp_confirm(request: Request, username: str = Depends(require_csrf)):
    form = await request.form()
    user = database.get_user(username)
    secret = user.get("totp_secret") if user else None
    step = auth.verify_totp(secret, str(form.get("code", ""))) if secret else None
    if step is None:
        setup = {"secret": secret, "svg": auth.totp_qr_svg(auth.totp_uri(secret, username))} if secret else None
        return _render_profile(request, username, error="That code did not match. Scan the QR code again and enter the current code.", setup=setup, status_code=400)
    database.confirm_totp(username, step)
    database.session_setup_done(request.cookies.get(auth.SESSION_COOKIE, ""))
    database.record_login(username)  # the first full login
    database.add_audit(username, client_ip(request), "mfa_setup", "TOTP confirmed")
    return _render_profile(request, username, message="Two-factor authentication is set up. You will be asked for a code at every login.")


# --- Admin: user management (full admin only) -------------------------------

def _render_users(request: Request, username: str, *, message: str = "", error: str = "",
                  new_password: tuple[str, str] | None = None, status_code: int = 200) -> Response:
    return _render(request, "admin_users.html", {
        "username": username, "csrf": request.state.csrf, "users": database.list_users(),
        "roles": database.ROLES, "message": message, "error": error, "new_password": new_password,
    }, status_code=status_code)


@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request, username: str = Depends(require_full_admin)):
    return _render_users(request, username)


_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")


@app.post("/admin/users/create")
async def admin_users_create(request: Request, username: str = Depends(require_csrf_admin)):
    form = await request.form()
    new_name = str(form.get("username", "")).strip().lower()
    role = str(form.get("role", "readonly"))
    if not _USERNAME_RE.fullmatch(new_name):
        return _render_users(request, username, error="Username: 2 to 32 characters, lowercase letters, digits, dot, dash or underscore.", status_code=400)
    if role not in database.ROLES:
        return _render_users(request, username, error="Unknown role.", status_code=400)
    password = secrets.token_urlsafe(12)
    try:
        database.create_user(new_name, await run_in_threadpool(auth.hash_password, password), role, username)
    except ValueError as exc:
        return _render_users(request, username, error=str(exc), status_code=400)
    database.add_audit(username, client_ip(request), "user_create", f"{new_name} ({role})")
    return _render_users(request, username, message=f"User {new_name} created with role {role}. They must set up two-factor authentication at first login.",
                         new_password=(new_name, password))


def _target_user(name: str) -> dict:
    user = database.get_user(name)
    if user is None:
        raise HTTPException(status_code=404, detail="No such user.")
    return user


@app.post("/admin/users/{name}/role")
async def admin_users_role(request: Request, name: str, username: str = Depends(require_csrf_admin)):
    form = await request.form()
    role = str(form.get("role", ""))
    _target_user(name)
    if role not in database.ROLES:
        return _render_users(request, username, error="Unknown role.", status_code=400)
    if role != "admin" and database.count_active_admins(excluding=name) == 0:
        return _render_users(request, username, error="That would leave no full admin.", status_code=400)
    database.set_role(name, role)
    database.add_audit(username, client_ip(request), "user_role", f"{name} -> {role}")
    return _render_users(request, username, message=f"{name} is now {role}.")


@app.post("/admin/users/{name}/password")
async def admin_users_password(request: Request, name: str, username: str = Depends(require_csrf_admin)):
    _target_user(name)
    password = secrets.token_urlsafe(12)
    database.set_password(name, await run_in_threadpool(auth.hash_password, password))
    database.delete_user_sessions(name)
    database.add_audit(username, client_ip(request), "user_password", f"{name}: new password issued")
    return _render_users(request, username, message=f"New password for {name}. Pass it on securely; it is shown only once.", new_password=(name, password))


@app.post("/admin/users/{name}/reset-mfa")
async def admin_users_reset_mfa(request: Request, name: str, username: str = Depends(require_csrf_admin)):
    _target_user(name)
    database.set_totp_secret(name, None)
    database.delete_user_sessions(name)
    database.add_audit(username, client_ip(request), "user_mfa_reset", name)
    return _render_users(request, username, message=f"Two-factor authentication for {name} was reset. They set it up again at next login.")


@app.post("/admin/users/{name}/disable")
async def admin_users_disable(request: Request, name: str, username: str = Depends(require_csrf_admin)):
    _target_user(name)
    if name == username:
        return _render_users(request, username, error="You cannot disable your own account.", status_code=400)
    if database.count_active_admins(excluding=name) == 0:
        return _render_users(request, username, error="That would leave no full admin.", status_code=400)
    database.set_disabled(name, True)
    database.add_audit(username, client_ip(request), "user_disable", name)
    return _render_users(request, username, message=f"{name} is disabled.")


@app.post("/admin/users/{name}/enable")
async def admin_users_enable(request: Request, name: str, username: str = Depends(require_csrf_admin)):
    _target_user(name)
    database.set_disabled(name, False)
    database.add_audit(username, client_ip(request), "user_enable", name)
    return _render_users(request, username, message=f"{name} is enabled.")


@app.post("/admin/users/{name}/delete")
async def admin_users_delete(request: Request, name: str, username: str = Depends(require_csrf_admin)):
    _target_user(name)
    if name == username:
        return _render_users(request, username, error="You cannot delete your own account.", status_code=400)
    if database.count_active_admins(excluding=name) == 0:
        return _render_users(request, username, error="That would leave no full admin.", status_code=400)
    database.delete_user(name)
    database.add_audit(username, client_ip(request), "user_delete", name)
    return _render_users(request, username, message=f"{name} is deleted.")


# --- Admin: the vehicle register ------------------------------------------

def _vin_or_404(vin: str) -> str:
    vin = vin.strip().upper()
    if not re.fullmatch(r"[A-HJ-NPR-Z0-9]{17}", vin):
        raise HTTPException(status_code=404, detail="Not a VIN.")
    return vin


@app.get("/admin/fleet", response_class=HTMLResponse)
def admin_fleet(request: Request, username: str = Depends(require_admin)):
    q = request.query_params
    filters = {
        "outcome": q.get("outcome", "") if q.get("outcome", "") in OUTCOMES else "",
        "trim": q.get("trim", "")[:1].upper(),
        "query": q.get("q", "")[:17],
        "anomalies": q.get("anomalies", "") == "1",
    }
    requirements = _current_requirements()
    if q.get("marlin_gap", "") == "1" and requirements is not None:
        filters["marlin_gap"] = requirements.profiles[-1]
    return _render(
        request, "admin_fleet.html",
        {
            "username": username, "csrf": request.state.csrf,
            "vehicles": database.fleet_vehicles(**filters), "min_readings": database.MIN_READINGS,
            "filters": filters, "outcomes": OUTCOMES, "trim_names": TRIM_NAMES,
            "module_ids": [m.id for m in requirements.modules] if requirements else [],
            "profiles": list(requirements.profiles) if requirements else [],
            "target": requirements.target_profile if requirements else "",
            "fleet": _fleet_stats(),
        },
    )


def _csv_response(filename: str, header: list[str], rows) -> StreamingResponse:
    """Streams a CSV with a UTF-8 BOM so Excel opens it with the right encoding."""
    def generate():
        buffer = io.StringIO()
        writer = csv.writer(buffer, delimiter=";", lineterminator="\r\n")
        buffer.write("\ufeff")
        writer.writerow(header)
        for row in rows:
            writer.writerow(row)
            if buffer.tell() > 64 * 1024:
                yield buffer.getvalue()
                buffer.seek(0)
                buffer.truncate()
        yield buffer.getvalue()

    return StreamingResponse(
        generate(), media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "private, no-store",
        },
    )


@app.get("/admin/fleet/vehicles.csv")
def admin_fleet_vehicles_csv(request: Request, username: str = Depends(require_admin)):
    requirements = _current_requirements()
    module_ids = [m.id for m in requirements.modules] if requirements else []
    header = [
        "vin", "trim", "last_upload_utc", "report_date", "uploads", "outcome",
        "complete_profile", "top_evidence", "country", "requirements_version",
    ] + [f"{m}_level" for m in module_ids] + [f"{m}_number" for m in module_ids] + [f"{m}_version" for m in module_ids]

    def rows():
        for v in database.fleet_vehicles():
            mods = v["modules"]
            yield [
                v["vin"], v["trim"], v["uploaded_at"], v["report_date"], v["uploads"], v["outcome"],
                v["complete_profile"] or "", v["top_evidence"] or "", v["country"], v["requirements_version"],
            ] + [
                (mods.get(m) or {}).get("level") or "" for m in module_ids
            ] + [
                "" if (mods.get(m) or {}).get("extracted") is None else mods[m]["extracted"] for m in module_ids
            ] + [
                (mods.get(m) or {}).get("version") or "" for m in module_ids
            ]

    stamp = datetime.now(UTC).strftime("%Y%m%d")
    database.add_audit(username, client_ip(request), "export", "vehicles.csv")
    return _csv_response(f"oceansoftwarecheck-vehicles_{stamp}.csv", header, rows())


@app.get("/admin/fleet/progress", response_class=HTMLResponse)
def admin_fleet_progress(request: Request, username: str = Depends(require_admin)):
    """Vehicles with more than one upload: how they moved and which modules
    were lifted between the first and the latest report."""
    return _render(
        request, "admin_progress.html",
        {
            "username": username, "csrf": request.state.csrf,
            "progress": database.fleet_progress(), "trim_names": TRIM_NAMES,
        },
    )


@app.get("/admin/fleet/progress.csv")
def admin_fleet_progress_csv(request: Request, username: str = Depends(require_admin)):
    header = ["vin", "uploads", "first_upload_utc", "first_outcome", "last_upload_utc", "last_outcome",
              "direction", "modules_lifted", "lifts"]
    rows = (
        [v["vin"], v["uploads"], v["first_at"], v["first_outcome"], v["last_at"], v["last_outcome"],
         v["direction"], len(v["lifts"]),
         " ".join(f"{x['module_id']} {x['from']}>{x['to']}" for x in v["lifts"])]
        for v in database.fleet_progress()["vehicles"]
    )
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    database.add_audit(username, client_ip(request), "export", "progress.csv")
    return _csv_response(f"oceansoftwarecheck-progress_{stamp}.csv", header, rows)


@app.get("/admin/fleet/readings.csv")
def admin_fleet_readings_csv(request: Request, username: str = Depends(require_admin)):
    header = [
        "submission_id", "vin", "uploaded_at_utc", "report_date", "trim", "outcome",
        "complete_profile", "top_evidence", "requirements_version", "country",
        "ecu_code", "ecu_name", "section", "module_id", "supplier_sw_version",
        "software_version", "hardware_version", "bootloader_version",
        "extracted_number", "level", "evidence_level", "status",
    ]
    rows = (
        [r[k] if r[k] is not None else "" for k in (
            "submission_id", "vin", "uploaded_at", "report_date", "trim", "outcome",
            "complete_profile", "top_evidence", "requirements_version", "country",
            "code", "raw_name", "section", "module_id", "supplier_sw",
            "software", "hardware", "bootloader", "extracted", "level", "evidence_level", "status",
        )]
        for r in database.export_readings()
    )
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    database.add_audit(username, client_ip(request), "export", "readings.csv")
    return _csv_response(f"oceansoftwarecheck-readings_{stamp}.csv", header, rows)


@app.get("/admin/fleet/{vin}", response_class=HTMLResponse)
def admin_vehicle(request: Request, vin: str, username: str = Depends(require_admin)):
    vin = _vin_or_404(vin)
    history = database.vehicle_history(vin)
    if not history:
        raise HTTPException(status_code=404, detail="No submissions for this VIN.")
    selected_id = request.query_params.get("s", "")
    selected = next((h for h in history if h["id"] == selected_id), history[0])
    odd = [r["module_id"] for r in selected["readings"] if r["module_id"] and r["status"] in ("missing", "unparseable", "empty")]
    return _render(
        request, "admin_vehicle.html",
        {
            "username": username, "csrf": request.state.csrf, "vin": vin,
            "history": history, "selected": selected, "trim_names": TRIM_NAMES,
            "odd_modules": odd, "few_readings": len(selected["readings"]) < database.MIN_READINGS,
            "min_readings": database.MIN_READINGS,
            "permanent_url": _permanent_url(request, database.link_key_for(vin)),
        },
    )


@app.post("/admin/fleet/{vin}/delete")
async def admin_vehicle_delete(request: Request, vin: str, username: str = Depends(require_csrf_admin)):
    vin = _vin_or_404(vin)
    files = database.delete_vehicle(vin)
    removed = 0
    for name in files:
        path = UPLOADS_DIR / Path(name).name
        try:
            path.unlink()
            removed += 1
        except FileNotFoundError:
            pass
    database.add_audit(
        username, client_ip(request), "vehicle_delete",
        f"VIN {vin}: {len(files)} submission file(s) referenced, {removed} removed from disk",
    )
    return RedirectResponse("/admin/fleet", status_code=303)


@app.post("/admin/merge-duplicates")
async def admin_merge_duplicates(request: Request, username: str = Depends(require_csrf_admin)):
    removed, files = await run_in_threadpool(database.merge_duplicate_submissions)
    deleted = 0
    for name in files:
        try:
            (UPLOADS_DIR / Path(name).name).unlink()
            deleted += 1
        except FileNotFoundError:
            pass
    database.add_audit(username, client_ip(request), "merge_duplicates",
                       f"{removed} duplicate upload(s) merged, {deleted} file(s) removed")
    return _render_admin(request, username, message=f"Merged {removed} duplicate upload(s) into the latest identical report; {deleted} file(s) removed.")


@app.post("/admin/reevaluate")
async def admin_reevaluate(request: Request, username: str = Depends(require_csrf_admin)):
    requirements = _current_requirements()
    if requirements is None:
        return _render_admin(request, username, error="Cannot re-evaluate: no valid requirements loaded.", status_code=503)
    count = await run_in_threadpool(database.reevaluate_all, requirements, UPLOADS_DIR)
    database.add_audit(
        username, client_ip(request), "reevaluate",
        f"{count} stored report(s) re-evaluated with requirements {requirements.version}",
    )
    return _render_admin(
        request, username,
        message=f"Re-evaluated {count} stored report(s) with requirements version {requirements.version}.",
    )
