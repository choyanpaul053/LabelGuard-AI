# LabelGuard AI — packaged-label review prototype

Responsive two-role prototype for checking a limited list of packaged-commodity declarations against a configurable rule checklist. The backend stores scan evidence in SQLite, runs vision extraction only, and makes deterministic field-presence checks in Python. Uncertain and unreadable scans are routed to a human review state.

> **Important:** This is a software prototype, not legal advice, official compliance certification, or an enforcement tool. The rule references and summaries in `rule_config.json` are a starting point, not a verified consolidated legal interpretation. India’s Legal Metrology (Packaged Commodities) Rules have amendments, exemptions, applicability conditions, and product-specific requirements. Have the exact current official text and mapping reviewed by a qualified Legal Metrology professional before relying on results. A single label photo may omit declarations on other package faces. This prototype makes no font-size, physical measurement, or packaging-safety assessment.

## Stack and features

- FastAPI backend + SQLite `scans` table
- Consumer: no account, browser-session UUID history, camera/file upload, scan states, field-by-field results
- Inspector: one environment-configured login, signed expiring token, dashboard, review queue, actions/notes, protected PDF reports
- OpenAI vision call extracts only configured fields; the deterministic rule engine creates verdicts separately
- Uploaded images are sent to the configured vision provider and retained locally in `uploads/` with scan records in SQLite; this prototype has no deletion/retention workflow yet
- No OCR package, RAG, vector database, rule-editor, consumer PDF, signup, or consumer login

## Run locally

1. Use Python 3.10 or newer.
2. Install dependencies: `python -m pip install -r requirements.txt`.
3. Copy `.env.example` to `.env`.
4. Set `OPENAI_API_KEY` in `.env` for image extraction. It is never placed in frontend code. Without a key, scans return the technical error state and are not saved.
5. Set a long random `JWT_SECRET`. The local-only seeded account is `inspector` / `LabelGuardDemo!2026`; the password is stored as a bcrypt hash in the backend. For any shared/deployed environment, set a unique `INSPECTOR_USERNAME` and `INSPECTOR_PASSWORD_HASH` in `.env`, plus a strong `JWT_SECRET`; never use the demo credentials.
6. Start the API and static site: `python -m uvicorn backend:app --reload --host 127.0.0.1 --port 3000`.
7. Open `http://127.0.0.1:3000`.

In VS Code, you can instead select **LabelGuard AI (open browser)** in Run and Debug and press **F5**. It starts the server and opens the app in your default browser once the server is ready.

For a custom bcrypt password hash, run `python -c "import bcrypt; print(bcrypt.hashpw(b'REPLACE_WITH_YOUR_PASSWORD', bcrypt.gensalt()).decode())"` locally, then put its output in `.env` as `INSPECTOR_PASSWORD_HASH`. Do not send credentials or API keys to anyone.

## Deploy publicly on Render

The local `127.0.0.1` address is only reachable from the computer running the app. To create a public HTTPS link:

1. Push this project to a private GitHub repository and connect it to Render using **New + → Blueprint**. Render reads `render.yaml` to create the web service and persistent disk.
2. In the Render service's environment settings, provide `OPENAI_API_KEY`, a unique `INSPECTOR_USERNAME`, and `INSPECTOR_PASSWORD_HASH`. Generate the password hash locally with the command above; do not use the demo inspector password or commit secrets to GitHub.
3. Wait for the deployment and health check to succeed. Render will show the public `https://...onrender.com` URL for the service. Open that URL on your phone or any other device.

The Blueprint stores SQLite data and uploaded evidence on a persistent disk. A public deployment may incur hosting and disk charges. Keep the API key and inspector credentials in Render's private environment settings, not in source files or frontend code.

## API routes

- `POST /api/scans` — multipart image upload; optional `X-Session-ID`
- `GET /api/history?session_id=<uuid>` — consumer session history
- `POST /api/login` — inspector login
- `GET /api/inspector/pending` — protected review queue
- `GET /api/inspector/dashboard` — protected aggregates
- `GET /api/inspector/scans/{id}` — protected scan detail
- `POST /api/inspector/scans/{id}/review` — protected approve/reject/annotate
- `GET /api/inspector/scans/{id}/report.pdf` — protected PDF report
- `GET /api/scans/{id}/image` — image evidence; inspector token or matching consumer session required
- `GET /api/health`, `GET /api/rules`

## Scan states

- `error`: extraction/API error; no scan record is created.
- `unreadable`: extraction returns at most one populated field; no rule validation occurs.
- `needs_review`: extraction is partial/low confidence; queued for inspector.
- `pass` / `fail`: the prototype presence checklist produced a preliminary result.

A missing extracted value does not prove the package is non-compliant; it may be on another panel, exempt, or missed by extraction. The UI and PDF keep that limitation visible.

## Files

- `backend.py` — API, vision extraction, static rule engine, auth, SQLite and PDF report
- `rule_config.json` — static, review-required rule references and scoped declaration fields
- `index.html`, `styles.css`, `app.js` — dark consumer and inspector UI
- `.env.example` — environment variable template (copy to ignored `.env`)
- `render.yaml` — Render Blueprint for the public web service and persistent data disk
