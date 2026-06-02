# AI Cyber Shield

AI Cyber Shield is a Flask-based phishing URL detection system using Random Forest
and Naive Bayes models. It extracts lexical, DNS, WHOIS, HTML, and JavaScript
features from public HTTP(S) URLs and stores scan history plus feedback in CSV
files.

## Structure

```text
app.py
config.py
requirements.txt
models/
services/
routes/
data/
templates/
static/
tests/
```

## Run Locally

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## API

- `POST /api/scan` with `{"url": "https://example.com"}`
- `GET /api/history?limit=25`
- `POST /api/feedback`

All API endpoints return JSON with proper status codes.

## Security Controls

- Only `http` and `https` URLs are accepted.
- Localhost, private, reserved, link-local, and non-global IP ranges are blocked.
- Redirect targets are validated before following.
- Response size, redirect count, and request timeouts are limited.
- CSV formula injection is neutralized before writing history or feedback.
- User-controlled frontend values are rendered with `textContent`, not HTML.
- CORS is not enabled by default. Add a strict origin allowlist if a separate
  frontend origin is introduced.

## Production Notes

- Set `SECRET_KEY` and keep `FLASK_DEBUG=0`.
- Serve with a WSGI server, for example:

```bash
waitress-serve --host=0.0.0.0 --port=5000 app:app
```

- Place the service behind a reverse proxy with TLS and rate limiting.
- Add egress firewall rules to enforce SSRF protections outside the process.
- Move CSV storage to SQLite or PostgreSQL before multi-worker deployment.
- Run scheduled model validation to catch feature drift.

## SQLite Migration Path

CSV repositories are append-only and simple, but they are not ideal for concurrent
production traffic. Replace `CsvRepository` with a repository using SQLite tables:

- `scan_history(url, forest_result, forest_risk, bayes_result, bayes_risk, final_result, time)`
- `feedback(url, predicted_result, user_feedback, actual_label, ml_label, forest_risk, bayes_risk, timestamp)`

Keep the same repository methods (`append`, `list_records`) so routes and services
do not need to change.
