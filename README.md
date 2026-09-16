# Ocean Software Check

Web portal for the Fisker Owners Association, renamed from "Marlin Readiness
Check" on 2026-09-13 (the URL stays): members upload an ECU diagnostics
report exported from **OceanLink Pro (OLP)**, and the portal checks whether the
car's control modules meet the minimum software levels required for the
**Marlin** software update. Live at <https://oceansoftwarecheck.com> (in production since 2026-09-16 after a BETA from 2026-09-05; marlin.flagan.net redirects there since 2026-09-15).

- Per-module result (OK / outdated / missing / version not recognised / empty
  field), one column per software release (2.0 / 2.1 / 2.2) with the minimum
  and a tick/cross, and one of five outcomes: **full 2.2** (Marlin-ready),
  **clean 2.1** (Marlin possible, 2.2 recommended first), **2.2 zebra**
  (started but incomplete 2.2), **2.1 zebra** (not Marlin-ready) or
  **already on Marlin** (VCU 2.4 detected). Each comes with the list of
  modules holding the car back and a recommendation.
- Trim read from the VIN (5th character): a Sport has no rear motor controller,
  so it is not counted as missing there. Battery management is checked per
  software line (NMC vs LFP pack).
- Result page laid out as the association's working group asked (Sep 2026):
  outcome and explanation, then the modules that must be updated for 2.2 (code
  first, current version and level, needed version and level), then only the
  highest complete level in green with every level above in red (counting the
  modules that do not meet), then the recommendation and a red contact line
  (service provider, or the regional/country liaison for full-2.2 cars). A zebra
  never gets a green Marlin line; a Marlin car still sees what it lacks for 2.2.
- Cars on Marlin also see whether the whole Marlin package is in place: the
  requirements file's `marlin_modules` (VCU 24, PDU 4000, FCM PSOP09, HYDRA
  ADAS039051, from the workbook's Marlin column and 7 of the 9 Marlin cars in
  the register) are checked and shown as a level line, a list of what is
  missing and a small table. Never part of the outcome; not counted on `/stats`
  yet (that would need re-evaluation to store it).
- Repeat uploads of the same VIN show what changed since the previous report
  (outcome and every control unit whose Supplier SW Version differs); the
  permanent link warns when the report is older than 60 days.
- A checklist PDF for service providers and FOA Advanced Installers
  (`/vehicle/<key>/workorder`): the modules to update in the recommended order
  (below 2.1 first, then below 2.2), current and needed version, the Marlin
  package for Marlin cars, the ESP/iBooster and multi-step notes, and a
  sign-off line. Offered only when there is something to update, and only
  while the switch in the admin console (Settings, table `settings`) is on.
- `/admin/analytics` shows the version distribution of every control unit in
  the latest reports, requirements or not.
- The admin register flags odd reports (a required module missing, empty or
  unrecognised, or fewer than 30 control units) with a filter and a notice on
  the vehicle page asking for a fresh OLP export.
- "Send me this result": the permanent link and the PDF to an address the
  member types in (`app/mail.py`). The address is used for that one message and
  not stored; 5 per IP per minute. A checkbox also attaches the checklist for
  service providers when that PDF is switched on. The admin console's Settings card holds the
  on/off switch, the SMTP relay (host, port, sender; Google Workspace's
  `smtp-relay.gmail.com` with STARTTLS, unauthenticated from a registered IP)
  and a "send a test e-mail" button. An empty relay host switches e-mail off.
- Downloadable PDF report (WeasyPrint), generated in the active language, with
  coloured ticks/crosses (the image has no emoji font) and without the permanent link.
- A permanent link per vehicle (`/vehicle/<random key>`, 128-bit key created on the
  first upload of a VIN and shown on the result page, in the PDF and in the admin
  register). It always renders the vehicle's latest stored report against the
  current requirements, so it survives restarts and requirement changes. There is
  deliberately no lookup by VIN: the register must not be enumerable.
- A public "How it works" page (`/how-it-works`) explaining the interpretation
  at processing level, in all languages.
- An upload identical to the vehicle's latest report (every control unit, all
  four version fields) refreshes that row instead of adding one (`upload_count`
  keeps the total); the admin console can merge older consecutive duplicates.
- Storage is mandatory (association decision, Sep 2026): every analyzed
  report goes into the **vehicle register** – file, VIN, all ECU version
  fields, outcome. Public dashboard (`/stats`, aggregated, no VINs) and an
  admin register with per-VIN history, filters, CSV exports, re-evaluation
  against changed requirements and deletion per VIN.
- Time series and fleet movement on `/admin/analytics`: uploads and distinct vehicles per
  day/week/month (pure-CSS charts, tabs without JavaScript), and for vehicles
  with more than one upload how they moved on the update ladder (2.1 zebra,
  clean 2.1, 2.2 zebra, full 2.2, on Marlin), which transitions occurred, how
  many modules were lifted, and the fleet's status month by month. The admin
  page `/admin/fleet/progress` lists the same per VIN with the lifted modules
  and a CSV export.
- 7 languages (en, nb, sv, da, de, fr, es) with browser auto-detection.
- Deterministic parsing and comparison – no LLMs involved.

## Repository layout

```
app/
  main.py       FastAPI app: routes, upload flow, admin (form login, CSRF), register, CSV
  parser.py     Parses the OLP "ECU Software Version Report" (PDF via pdfplumber, or text)
  rules.py      Rule engine: profile-based requirements, variants, trims, Marlin marker,
                outcome classification, validation of the YAML
  db.py         SQLite: vehicle register (submissions + all module readings), fleet
                statistics, re-evaluation, usage stats, audit log, admin sessions
  auth.py       Credentials (PBKDF2), login lockout, TOTP helpers, trusted client-IP header
  passkeys.py   WebAuthn (passkeys) wrapper around py_webauthn
  i18n.py       Language negotiation + JSON dictionaries in app/locales/
  templates/    Jinja2: base, index, result (+ _result_body), how, stats, privacy; admin pages
                (overview, requirements, settings, analytics, log, fleet, vehicle, progress,
                users, profile, login, login_code) with _admin_nav and _fleet_tiles; pdf and
                workorder (standalone, rendered by WeasyPrint with their own styles)
  static/       style.css (dark theme after fiskeroa.com, light variant via prefers-color-scheme)
                and app.js (all page JS; no inline scripts, CSP-enforced), fonts/ (self-hosted
                Titillium Web, OFL), img/ (FOA logo, see img/SOURCES.md), favicon (generated "OSC" mark),
                the two front-page videos (olp-howto-nb/-en.mp4 + posters; nb gets the
                Norwegian one, every other language the English one) and the dongle photo
tests/          pytest suite. Fixtures: a real OLP export (olp_report.pdf, unmodified)
                and its text extraction with an anonymized VIN, plus synthetic
                reference cars (100% 2.1, full 2.2, two Marlin cars) built from it
scripts/        hash_password.py (YAML rescue users), manage_users.py (users in the database)
requirements.example.yaml   the requirements spec with field documentation
requirements.txt / .lock    loose spec / pinned+hashed set used by Docker and CI
pyproject.toml              ruff configuration
```

## Look and feel

Since 2026-09-16 the portal follows the association's website (fiskeroa.com):
near-black background (#181818, cards #212121, header #111), white text,
self-hosted Titillium Web, FOA orange (#f78e1e) as the accent under the active
navigation item and blue (#1863dc) buttons. A light palette is applied
automatically when the visitor's system prefers it (`prefers-color-scheme`;
header and footer stay dark), and a print palette makes `/stats` and result
pages readable on paper. Everything is driven by CSS custom properties at the
top of `static/style.css`; the outcome colours (Marlin blue, full 2.2 green,
clean 2.1 purple, 2.2 zebra orange, 2.1 zebra magenta) keep their hues in both
themes. The header shows the FOA community logo; the favicon is a generated
"OSC" mark. The layout is responsive (breakpoints at 1000 px for the header
and 760 px for the rest) with 44 px touch targets. The PDF and work-order
documents are unchanged by the theme.

## Status

| Area | State |
|---|---|
| Parser | Verified against a real OLP PDF export (fixture) and the uploads of the BETA period |
| Requirements | The association's minimum table (2.0/2.1/2.2) plus iBooster as the eighth critical module (2026-09-13, ESP and iBooster must be on the same generation); ECC 2.2 = 25 since 2026-09-14. Verified against real cars sitting exactly at the 2.1 minimums, on full 2.2 and on Marlin. Open points are listed below and tracked in the `notes:` field of the requirements file |
| Trim logic | Verified for One (Z), Extreme (E, 2026-09-12) and Ultra (U, 2026-09-13) by real uploads, all on the NMC battery line as expected; the Sport case (VIN letter S, no MCU_R, BMSL battery line) awaits a real Sport report |
| Deployment | Automatic: push to `main` → tests → image → Portainer webhook → new container (see below) |

## Open points (2026-09-13)

Waiting on the association (Jens):

1. **BCM 41 vs 42**: one Marlin car shows BCM 41 where the table says 42
   for 2.2.
2. **Sport**: the LFP BMS level (15) rests on one reference report, and the
   trim letter S has never been seen in a real upload. S is the letter that
   exempts MCU_R, so this is the one trim rule that is still unverified.
3. **Privacy**: controller/contact and retention period for the register
   (see Privacy model below).

Resolved 2026-09-14 by re-reading the association's workbook and the 36 cars in
the uploads folder: ECC at 2.2 is **25** (the workbook's own 2.2 report and
every fully updated 2.2 car say 25; the hand-written table had 24), iBooster
401 is confirmed by the workbook, the 2.0 column is correct, and the 2.1
profile as the direct-Marlin requirement is stated in words.

The BETA banner was removed 2026-09-16; the data was kept (identical uploads
merged instead of a reset). Pre-v2 rows show country "(unknown)" on `/stats`
because country was not stored before v2; left as is.

## How the check works (short)

Outcomes (rule engine, `app/rules.py`): each module gets `meets[profile]`
and an `evidence_level` – the LOWEST profile that shares the minimum of the
highest profile the module satisfies, so a module whose 2.1 and 2.2 minimums
are equal (ECC 24, BMS 21) never counts as proof of 2.2. Per car:
`complete_profile` (highest profile every critical module meets) and
`top_evidence` (highest evidence over the modules). Then: VCU at the Marlin
level → `marlin`; complete = 2.2 → `full_22`; complete = 2.1 and evidence
2.1 → `full_21`; complete = 2.1 and evidence 2.2 → `zebra_22`; anything
below 2.1 → `zebra_21`. The old `verdict` (ready/zebra/marlin) is derived
from the same data and kept for compatibility.


The parser reads the OLP report: sections (BODY/INFOTAINMENT/POWERTRAIN/CHASSIS/ADAS),
ECU blocks (`CODE - Name`) and the **Supplier SW Version** field, which is
the only field compared against the requirements. A module-specific `extract`
regex turns that text into a number (`BCM395030` → 30, `ECC395 24` → 24,
`89324V0402…` → 402). Anything the regex does not recognise is "version not
recognised" and counts as failing; doubt never yields "ready".

The requirements are profile-based (2.0/2.1/2.2) and cover eight modules: BCM,
ESP, iBooster (IBS), ECC, BMS, MCU_F, MCU_R and VCU. iBooster was added on
2026-09-13 because ESP and iBooster are Bosch units that must be flashed to the
same generation: a car with ESP at the 2.2 level (501) but iBooster still on
the 2.1 line (400 instead of 401) is a 2.2 zebra. A car that reaches the 2.1
level on all eight required modules is "100% 2.1" and can be updated directly
to Marlin; otherwise it is a zebra and must go via SW 2.2 first. A ready car is
also shown which modules sit below the 2.2 level (a direct 2.1→Marlin update
leaves those behind). A car whose VCU is at the Marlin level (`marlin_level:
24` on VCU) gets the informational "already on Marlin" verdict. The full,
member-facing explanation is the `/how-it-works` page; the field documentation
is in `requirements.example.yaml`.

## The requirements file

`requirements.example.yaml` defines the module requirements. In production it
lives as `/config/requirements.yaml` (bind-mounted directory). It is re-read
on every analysis, so requirements can be updated **without** a rebuild –
either directly on the host or via the admin page. Per module: `match` (ECU
codes), `extract` (regex with one capture group), `levels` per profile,
`critical`, optional `variants` (parallel software lines, e.g. BMS NMC/LFP),
`only_trims` (e.g. MCU_R only on Z/E/U) and `marlin_level`. The top-level
`notes:` field holds sources and open points and survives form-editor saves,
unlike YAML comments.

The profile names are effectively fixed: the result-page texts in all seven
languages are written for target profile `2.1` and highest profile `2.2`. The
rule engine does not care, but if the profiles ever change, the texts in
`app/locales/*.json` (`verdict_ready_text`, `verdict_zebra_text`,
`ready_22_note`, `verdict_marlin_text`, `marlin_below_top_note`) must be
rewritten; the admin page warns when the file deviates from these names.

The YAML is type-validated on load (lists, mappings, integer levels, regexes
with a capture group, a level for the target profile). If the file on disk
becomes invalid or unreadable, analyses keep using the last valid set loaded
since startup, `/healthz` returns 503 with the error (the container shows as
unhealthy), and the admin page shows the error above the YAML editor. If no
valid set has been loaded at all, uploads get a friendly 503 page.

## Admin console (`/admin`)

One page per task, linked from the bar at the top of every admin page:
Overview (`/admin`: register tiles, merge duplicates, re-evaluate all),
Requirements (`/admin/requirements`), Settings (`/admin/settings`), Vehicle
register (`/admin/fleet`), Analytics (`/admin/analytics`: Marlin cars split by full 2.2 and
Marlin package, what holds the split cars back, every control unit, uploads
over time, fleet movement, usage count), Activity log (`/admin/log`), Users and My account.

- **Login:** form login at `/admin/login`, then a second factor (TOTP code
  or passkey; see "Admin users, roles and MFA"). Users live in the database
  and are managed on `/admin/users`; `/config/admin_users.yaml` (see
  `admin_users.example.yaml`, hashes from `python3 scripts/hash_password.py`)
  only seeds the first start and serves as a rescue entrance. Failed attempts
  are locked out after 10 per 15 min, per IP and per username. Sessions live in SQLite (only a hash of
  the cookie token is stored) behind an `HttpOnly; Secure; SameSite=Lax`
  cookie scoped to `/admin`, expire after 8 h idle or 24 h total, and "Log
  out" deletes them. Admin POSTs are CSRF-protected three ways: the SameSite
  cookie, a `Sec-Fetch-Site` check and a per-session token in every form.
- **Editing:** a form editor (one row per module) plus a raw YAML editor.
  Everything is validated before saving; invalid content is rejected without
  touching the file. Saves are atomic and take effect on the next analysis.
  The form editor preserves `variants`, `only_trims`, `marlin_level` and
  `notes`; edit those in the YAML editor.
- **Activity log (`/admin/log`):** saves (with unified diff), logins,
  logouts, exports, settings and register actions, with timestamp, username
  and client IP.
- **Vehicle register (`/admin/fleet`):** one row per VIN (latest upload)
  with outcome, complete/evidence profile and the extracted level of every
  required module; filter by outcome, trim and VIN. `/admin/fleet/<VIN>`
  shows the upload history and the full module table (all four version
  fields) of any upload, and can delete every record and file for that VIN
  (audited). Exports: `vehicles.csv` (one row per car) and `readings.csv`
  (one row per ECU per upload), semicolon-separated with a UTF-8 BOM.
- **Re-evaluate all:** parses every stored report again from its file
  (falling back to the stored readings when the file is gone), re-runs the
  current requirements and rewrites outcome, levels and Marlin package state.
  Run it after changing levels or after a portal update that changes how
  reports are read.
- **Usage statistics (on Analytics):** anonymous per-upload counters (country from
  Cloudflare's `CF-IPCountry`, language, outcome, keyed daily IP hash for
  unique users – see "Privacy model"). Never VIN, report content or raw IP.

## Security notes

- Uploads: 15 MB limit enforced from `Content-Length` before the body is read,
  chunked read up to the limit, PDFs over 20 pages rejected before text
  extraction; parsing runs in the threadpool so a slow PDF never blocks other
  visitors. Rate limit of 10 uploads per minute per IP.
- The client IP comes from ONE trusted header (`OSC_CLIENT_IP_HEADER`,
  default `cf-connecting-ip`). `X-Forwarded-For` is never used: Cloudflare
  appends to a client-supplied value, so its first element is attacker
  controlled.
- Every response carries a Content-Security-Policy with no inline scripts
  (all JS is in `static/app.js`), `X-Content-Type-Options`, `X-Frame-Options`
  and `Referrer-Policy`. Result and PDF responses are `Cache-Control: no-store`.
- The upload redirects straight to the vehicle's permanent link (128-bit random
  key); the old `/result/<token>` links answer 410 with an explanation.

## Running locally

```bash
docker compose up --build
```

Open <http://localhost:8000>. Test with `tests/fixtures/olp_report.pdf` (a
real OLP export from a Fisker Ocean One) or `olp_report.txt` (its text
extraction with an anonymized VIN). For the admin page, copy
`requirements.example.yaml` to `dev-config/requirements.yaml` and create
`dev-config/admin_users.yaml` (see `admin_users.example.yaml`); `dev-config/`
is git-ignored.

Without Docker (PDF download requires pango/cairo installed):

```bash
pip install -r requirements.lock pytest httpx ruff
ruff check .
pytest
uvicorn app.main:app --reload
```

`requirements.txt` is the loose dependency spec; `requirements.lock` is the
fully pinned, hash-checked set that the Docker image and CI install. After
changing `requirements.txt`, regenerate the lock with
`uv pip compile requirements.txt --python-version 3.12 --python-platform linux --generate-hashes -o requirements.lock`.

## Environment variables

All variables are read as `OSC_<NAME>`. The pre-rename `MARLIN_<NAME>` names
still work (with a deprecation warning in the log) so a deployment can switch
at its own pace.

| Variable | Default in code | In the Docker image | Description |
|---|---|---|---|
| `OSC_DATA_DIR` | `./data` | `/data` | SQLite database (`oceansoftwarecheck.sqlite3`; a `marlin.sqlite3` from before the rename is moved automatically on first start) |
| `OSC_UPLOADS_DIR` | `./data/uploads` | `/data/uploads` | Stored report files |
| `OSC_REQUIREMENTS_PATH` | `./requirements.example.yaml` | `/config/requirements.yaml` | The requirements file |
| `OSC_ADMIN_USERS_PATH` | `/config/admin_users.yaml` | same | Admin users (PBKDF2 hashes) |
| `OSC_COOKIE_SECURE` | `1` | same | Mark the admin session cookie `Secure`. Set to `0` only for local development over plain http (compose.yml does). |
| `OSC_PUBLIC_URL` | (empty) | same | Absolute base for the permanent vehicle links, e.g. `https://oceansoftwarecheck.com`. Empty = derived from `X-Forwarded-Proto` and `Host`, which the Cloudflare tunnel provides. |
| `OSC_SMTP_HOST` | (empty) | same | Optional seed for the SMTP relay setting on first start (e.g. `smtp-relay.gmail.com`). The relay is otherwise configured in the admin console under Settings. |
| `OSC_SMTP_PORT` | `587` | same | Optional seed for the relay port setting. |
| `OSC_MAIL_FROM` | `Ocean Software Check <noreply@oceansoftwarecheck.com>` | same | Optional seed for the sender setting; must belong to a domain the relay accepts. |
| `OSC_MAX_HEAVY_JOBS` | `4` | same | How many report analyses and PDF renderings may run at once; further requests wait in line. Protects the container's memory limit under a burst of uploads. |
| `OSC_CLIENT_IP_HEADER` | `cf-connecting-ip` | same | The one request header trusted for the client IP (rate limits, login lockout, audit log, usage hash). Set to empty to use the socket address when no proxy is in front. |

## Build and deploy

Renamed 2026-09-16 from `marlin-check` to `oceansoftwarecheck`: repository,
image, Portainer stack, environment variables (`OSC_*`), database file, admin
session cookie (`osc_admin`, so every admin logs in again once) and CSV file
names. The old repository URL redirects.

GitHub Actions (`.github/workflows/build.yml`, actions pinned to commit SHAs)
runs ruff and the test suite, builds and publishes
`ghcr.io/terjefl/oceansoftwarecheck` (`latest` + git SHA) on every push to `main`,
and then calls a Portainer stack webhook (repo secret `PORTAINER_WEBHOOK_URL`)
that re-pulls the image and recreates the container. A push is live about a
minute after a green build. The deploy step is a no-op when the secret is
absent, so forks build without deploying.

The container is self-contained: mount a data directory on `/data` and a
config directory on `/config` (with `requirements.yaml` and
`admin_users.yaml`), publish port 8000, and put it behind an HTTPS reverse
proxy that sets the trusted client-IP header. Country statistics use
Cloudflare's `CF-IPCountry` header and degrade gracefully without it.
Production runs as a Portainer git stack behind a Cloudflare Tunnel; the
compose file lives in the operator's infrastructure repo.

Heavy work (PDF parsing, WeasyPrint) is capped at `OSC_MAX_HEAVY_JOBS`
concurrent jobs (default 4); a burst of uploads queues rather than fanning out
over the threadpool. Measured on a laptop: ~0.12 s per PDF analysis, 40
parallel uploads complete in ~5 s with no errors.

Run exactly **one** uvicorn worker/replica: the upload and e-mail rate
limits, the admin login lockout and the daily usage-hash key live in process
memory. A restart loses nothing visible to members (results are the permanent
vehicle links in the database). The origin must only be reachable through the
proxy that sets the trusted client-IP header.

## Admin users, roles and MFA

Admin accounts live in the database (table `admin_users`) and are managed on
`/admin/users` by a full admin: create (a password is generated and shown
once), set role, issue a new password, reset two-factor, disable, delete. Two
roles: **admin** (change requirements, re-evaluate, delete vehicles, manage
users) and **readonly** (sees everything, including exports, changes nothing;
state-changing routes answer 403). Nobody can delete or disable themselves or
the last active full admin. Every action goes to the audit log.

Two-factor authentication (TOTP, RFC 6238) is required for every account.
Login is password first, then the six-digit code (`/admin/login/code`); a
session that still owes the code lives 10 minutes. An account without MFA is
sent to `/admin/profile` and can do nothing else until a code has been
confirmed. Codes are accepted once (the time step is stored) and one step
either side for clock drift; wrong codes count towards the same lockout as
wrong passwords. Users change their own password and move to a new phone on
`/admin/profile`.

Passkeys (WebAuthn, `py_webauthn`, `app/passkeys.py`): a user adds one on
`/admin/profile` (discoverable credential with user verification, so Face ID,
Touch ID, Windows Hello, security keys and password managers all work). A
passkey counts as the second factor instead of a TOTP code on
`/admin/login/code`, and signs in on its own from the login page ("Sign in with
a passkey"), which creates an anonymous pending session that is promoted once
the signature verifies. A passkey alone satisfies the MFA requirement; the only
remaining second factor cannot be removed. The relying-party id is the site's
host name (`OSC_PUBLIC_URL` or the forwarded host), so passkeys registered
on one domain do not work on another. The challenge is stored on the session
row and consumed once; sign counts are tracked. All JavaScript is in
`static/app.js` (CSP-compliant); the JSON endpoints require `Sec-Fetch-Site:
same-origin` and, for the profile, the CSRF token in `X-CSRF-Token`.

Bootstrap and rescue: on the first start with an empty table, the users in
`admin_users.yaml` are imported as full admins without MFA. A user that exists
only in the YAML file can still log in (rescue entrance) and is asked to set up
MFA. `scripts/manage_users.py` (`list`, `add`, `set-password`, `set-role`,
`reset-mfa`, `enable`, `disable`, `delete`) works directly on the database on
the host, for when nobody can log in.

## Privacy model

- Storage is mandatory: the member must tick the acceptance box, otherwise
  the upload is refused (422) and nothing is stored. The result page is the
  vehicle's permanent link; whoever has the link can see the latest report. Every analyzed report is
  stored: the file, the VIN, every ECU block with all four version fields,
  trim, outcome, upload country (`CF-IPCountry`) and time.
- The database schema is migrated in place on startup (additive `ALTER
  TABLE`); rows from the consent period are kept and get an outcome after
  "Re-evaluate all" in the admin page.
- `/stats` is public and aggregated (outcomes, level per module, trims,
  countries) – never a VIN. The working-group detail (split cars per module,
  every control unit, uploads over time, fleet movement) is admin-only on
  `/admin/analytics`. VINs are visible only in the admin register. Deletion per VIN is an admin action.
- Anonymous usage counting per upload (admin-only view): country, language,
  outcome, and a keyed daily hash of the IP for unique-user counts. The HMAC
  key is random, lives only in process memory and is replaced at the UTC day
  rollover and on restart, so a stored hash cannot be brute-forced back to an
  IP. No VIN, no report data, no raw IP.
- "Send me this result" e-mails the permanent link and the PDF to an address
  the member types in; the address is used for that one message, never stored,
  and the feature is rate-limited and can be switched off in Settings.
- Open: the privacy page does not yet name a controller/contact or a
  retention period; these await the association's decision. The deletion
  routine exists (admin, per VIN).

## License

MIT (see `LICENSE`). The Fisker Owners Association and anyone else may use,
copy, modify and host the code. The FOA logo in `app/static/img/` and the
OLP report fixture in `tests/fixtures/` are not covered by the licence:
the logo belongs to the association, and the report belongs to its owner.
Titillium Web in `app/static/fonts/` is under the SIL Open Font License
(`fonts/OFL.txt`).
