# CxOne-Preset-Manager-Console

A local Flask web app for comparing Checkmarx One SAST presets.

## Features

- Sign in with a Client ID/Secret or an API Key (region-configurable base/IAM URLs).
- One-click sync pulls all presets from your tenant into a local SQLite cache, with
  visually distinct badges for Built-in vs. Custom presets.
- Compare any two presets: differing queries are grouped by language and category,
  matching how the Checkmarx One preset editor organizes queries.
- Export a preset diff to CSV (`Language, Category, Query Name, Query Information`).
- Export any preset as JSON in the same shape returned by
  `GET /api/preset-manager/sast/presets/{id}`.
- Update a preset by submitting a JSON list of queries to add, with a preview/confirm
  step before anything is sent to your tenant.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Then open http://localhost:5050 and sign in.

### Optional: skip re-entering credentials with a .env file

```bash
cp .env.example .env
# edit .env and fill in CX_TENANT plus either CX_API_KEY or CX_CLIENT_ID/CX_CLIENT_SECRET
```

When a usable set of credentials is found in `.env`, the login page shows a
"Sign in using .env credentials" button so you don't have to retype them. You can
still sign in manually with different credentials at any time — `.env` is only a
convenience default, not a requirement.

## Notes

- `.env` is gitignored. It holds credentials in plaintext on disk, so only use it on a
  machine you trust and never commit it.
- Once signed in (either manually or via `.env`), credentials are held in server memory
  only for the life of the process — never written to disk beyond `.env` itself.
- `cx_client.py` isolates all Checkmarx One API calls (auth, list/get/update presets,
  query-family catalog).
- **Preset query shape**: a preset's `queries` field groups ids by family (language)
  rather than embedding query metadata directly:
  `"queries": [{"familyName": "Java", "queryIds": ["123", ...]}, ...]`. Syncing therefore
  does two things: it pulls every query family and its queries
  (`/api/preset-manager/sast/query-families` and `.../query-families/{family}/queries`)
  into a local catalog, then pulls presets. `models.normalize_preset_queries()` resolves
  a preset's bare ids against that catalog to get language/category/name/severity for
  the compare view, CSV export, and the preset detail panel. An id with no catalog match
  still renders (labeled with its family and a placeholder name) instead of being dropped.
- Updating a preset (`PATCH /api/preset-manager/sast/presets/{id}`) sends the same
  grouped-by-family shape that Checkmarx's own preset-creation endpoint uses.
