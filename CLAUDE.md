# CLAUDE.md

Project context for Claude Code. `README.md` is the full reference (features,
rule engine, admin console, security, privacy, deployment); this file holds
what is not obvious from the code and the working rules for this repo.

## What this is

Ocean Software Check: a FastAPI portal for the Fisker Owners Association (FOA).
Members upload an OceanLink Pro (OLP) ECU report; the portal checks whether the
car's control modules meet the minimum software levels for the Marlin update
and stores every report in the association's vehicle register. Live at
https://oceansoftwarecheck.com, in production since 2026-09-16, hosted and
maintained by Terje (owner of this repo). Jens (FOA) is the association's
contact and decides on requirements, texts and privacy questions.

Renamed from "marlin-check" on 2026-09-16 (repo, image, `OSC_*` env vars,
database file, cookie). `MARLIN_*` env vars still work as a fallback.

## Commands

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r requirements.lock pytest httpx ruff
.venv/bin/ruff check .
DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib .venv/bin/pytest -q
```

- Run ruff AND pytest before every commit. CI runs both and blocks deploy.
- On macOS the PDF tests need `brew install pango cairo` and the
  `DYLD_FALLBACK_LIBRARY_PATH` above, otherwise 7 WeasyPrint tests fail with
  "cannot load library libgobject-2.0-0". Linux only needs the pango packages.
- Local server: `docker compose up --build` (port 8000), or
  `.venv/bin/uvicorn app.main:app --reload`. For `/admin` locally, copy
  `requirements.example.yaml` to `dev-config/requirements.yaml` and create
  `dev-config/admin_users.yaml`; `dev-config/` and `dev-data/` are git-ignored.
- After changing `requirements.txt`, regenerate the lock:
  `uv pip compile requirements.txt --python-version 3.12 --python-platform linux --generate-hashes -o requirements.lock`

## Deploy: a push to main is a production release

GitHub Actions tests, builds `ghcr.io/terjefl/oceansoftwarecheck` and calls a
Portainer webhook; the new container is live about a minute after a green
build. There is no staging. Therefore:

- Never push without Terje asking for it. Commit locally, say what is pending.
- A restart is harmless since 2026-09-16 (result links are permanent, in the
  database), but avoid pushing right after an FOA newsletter goes out.
- The production requirements file (`/config/requirements.yaml`) and admin
  users live outside the repo on the host. Changing `requirements.example.yaml`
  does not change production; Terje updates prod via `/admin` or scp, then
  presses "Re-evaluate all". Say so whenever a change touches requirements.
- Claude cannot SSH into the production host or exec into the container.
  Terje runs those steps himself.

## Code conventions

- One process, one uvicorn worker: rate limits and login lockout live in memory.
- No inline JavaScript anywhere. CSP is enforced; all JS goes in
  `app/static/app.js`. No external CDNs, fonts are self-hosted.
- Seven locales in `app/locales/*.json` (en, nb, sv, da, de, fr, es). Every
  new user-facing string needs a key in all seven. Tests check the
  how-it-works page in every language. Write English first; nb, sv, da, de,
  fr, es follow. sv, da and fr texts were reviewed by native speakers in
  September 2026, so edit those with care and keep their wording.
- Text style (Terje's rules): en dash, never em dash (ruff RUF001/RUF002
  also rejects them in Python strings). Active headings, no formula notation,
  no ALL CAPS, one thought per sentence, screen names capitalised.
- The profile names 2.0/2.1/2.2 are effectively fixed: locale texts are
  written for target 2.1 and top 2.2.
- Doubt never yields "ready": an unrecognised or empty version counts as
  failing. Keep the rule engine pessimistic.
- Theme: `style.css` is dark with an automatic light variant via
  `prefers-color-scheme`. `pdf.html` and `workorder.html` have their own
  print styling and are untouched by the theme.
- FOA assets in `app/static/img` are the association's; log every addition
  in `img/SOURCES.md`.
- Additive SQLite migrations only (`ALTER TABLE` in `db.py` on startup).
  Never a migration that drops or rewrites rows.

## Data handling

- The register holds real VINs and full ECU data. Never copy member uploads
  or production data into the repo, tests or commit messages, and never print
  VINs in output. The test fixtures are the only allowed reports (one real
  PDF, Terje's own car by his choice; the text fixtures have anonymised VINs).
- There is deliberately no lookup by VIN; the register must not be
  enumerable. Do not add one without a board decision.
- The address in "Send me this result" is used once and never stored.

## Open points (as of 2026-09-16)

Waiting on Jens: BCM 41 vs 42 on one Marlin car; a real Sport (VIN letter S)
report to verify the MCU_R exemption and the LFP BMS level; controller and
retention text for the privacy page. Backlog ideas: region liaison overview,
`/stats.json`, batch upload, Marlin package in stats, healthz monitoring.
Update this section and the README's open points together.
