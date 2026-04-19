# PromptShield: Real-Time GenAI Privacy Guard

PromptShield is a full-stack capstone application that acts as a runtime privacy layer between end users and GenAI systems. It runs a multilingual ML-first classifier with heuristic fallback, sanitizes prompts and model outputs, keeps reversible pseudonym mappings encrypted, logs only safe metadata, and quantifies privacy-utility-latency tradeoffs.

## Why This Capstone Stands Out

- Multilingual ML-first detection for English, Urdu, and Roman Urdu (with confidence-gated heuristic fallback).
- Conversation-consistent pseudonymization (`[PERSON_1]`, `[PHONE_1]`, etc.) across turns.
- Adversarial exfiltration lab with prompt injection and extraction attempts.
- Secure logging architecture that avoids raw secret/PII persistence.
- Evaluation suite with privacy, utility, leakage, false-positive, and latency metrics.
- Product-style command center UI for realistic demo storytelling.

## Monorepo Structure

```
.
├── api/                     # FastAPI backend
│   ├── app/
│   │   ├── api/             # REST routes and dependencies
│   │   ├── core/            # config, security, rate limiting
│   │   ├── db/              # SQLAlchemy models and session
│   │   ├── schemas/         # Pydantic API contracts
│   │   └── services/        # detector, pseudonymizer, audit, metrics, eval
│   ├── scripts/             # evaluation runner
│   └── tests/               # pytest suite
├── web/                     # Next.js 14 frontend (App Router)
│   ├── app/                 # landing + dashboard pages
│   ├── components/          # shared UI and chart components
│   └── lib/                 # typed API client and utils
├── data/
│   ├── demo_samples.json
│   ├── adversarial/cases.json
│   └── evaluation/
├── docs/                    # architecture and methodology docs
└── scripts/                 # convenience PowerShell scripts
```

## Tech Stack

### Frontend
- Next.js 14 (App Router), TypeScript
- Tailwind CSS, Framer Motion
- Recharts for metrics visualization
- Lucide icons, Sonner notifications

### Backend
- FastAPI, Pydantic, SQLAlchemy
- SQLite (local default)
- Fernet encryption for mapping storage
- Signed admin cookie + CSRF token checks
- In-memory request throttling middleware

### Testing and Evaluation
- `pytest` backend tests
- `vitest` frontend unit tests
- Dataset-driven evaluation and adversarial suites

## Core Features

1. Real-Time Chatbot
- Multi-turn simulation with stable placeholders in-session.
- Inline warnings for unsafe prompt injection and output leakage.
- Dynamic allow/mask/block decisions with label, confidence, language, and action trace.

2. Model Output Guard
- Detect leakage in model outputs.
- Redact/block risky output with reason.

3. Metrics Dashboard
- Precision, recall, F1, FPR, leakage, utility.
- Average/p50/p95 latency and mode comparison charts.
- Blocked-rate, fallback-rate, unsafe-rate, and label distribution KPIs.

4. Audit Trail
- Search/filter by session, event type, risk, timestamp.
- Logs input (PII-safe masked form), language, predicted label, confidence, PII status, and final decision.
- CSV export with safe metadata only.

## API Endpoints

- `GET /api/v1/health`
- `POST /api/v1/shield/analyze`
- `POST /api/v1/shield/redact`
- `POST /api/v1/shield/pseudonymize`
- `POST /api/v1/shield/process`
- `POST /api/v1/shield/output/analyze`
- `POST /api/v1/shield/chat/simulate`
- `POST /api/v1/adversarial/run`
- `GET /api/v1/adversarial/latest`
- `GET /api/v1/metrics/dashboard`
- `POST /api/v1/metrics/evaluation/run`
- `GET /api/v1/metrics/evaluation/latest`
- `GET /api/v1/audit/logs`
- `GET /api/v1/audit/export.csv`
- `POST /api/v1/admin/auth/login`
- `POST /api/v1/admin/auth/logout`
- `GET /api/v1/admin/auth/me`
- `GET /api/v1/admin/settings`
- `PUT /api/v1/admin/settings`
- `GET /api/v1/admin/mappings/{session_id}`
- `DELETE /api/v1/admin/mappings/{session_id}`
- `GET /api/v1/admin/sessions`
- `GET /api/v1/demo/samples`
- `GET /api/v1/demo/walkthrough`

## Quick Start (Recommended)

1. Create env file:
```powershell
Copy-Item .env.example .env
```
2. Start everything:
```powershell
.\scripts\start-local.ps1 -InstallDeps
```
3. Open:
- Web: `http://localhost:3000`
- API docs: `http://localhost:8000/docs`

## Manual Local Setup

### Backend
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r api\requirements.txt
Copy-Item api\.env.example api\.env
Push-Location api
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
Pop-Location
```

### Frontend
```powershell
Push-Location web
npm install
Copy-Item .env.example .env.local
npm run dev
Pop-Location
```

## Environment Variables

Defined in `.env.example`:

- `NEXT_PUBLIC_API_URL`
- `APP_NAME`
- `API_PREFIX`
- `DEMO_MODE`
- `DATABASE_URL`
- `APP_SECRET`
- `MAPPING_ENCRYPTION_KEY`
- `ADMIN_PASSWORD`
- `CORS_ORIGINS`
- `RATE_LIMIT_WINDOW_SECONDS`
- `RATE_LIMIT_MAX_REQUESTS`
- `MAX_TEXT_LENGTH`
- `DEFAULT_MODE`

## Demo Walkthrough

1. Open the app; it redirects directly to the secure chatbot.
2. Send multilingual prompts and verify chat always runs in `combined` mode.
3. Show masked prompt output and guarded assistant responses per turn.
4. Open Metrics and present privacy-utility-latency chart comparisons.
5. Open Audit Trail and export CSV evidence.

## Running Tests

### Backend
```powershell
Push-Location api
python -m pytest
Pop-Location
```

### Frontend
```powershell
Push-Location web
npm run test
Pop-Location
```

## Running Evaluation Suite

```powershell
Push-Location api
python -m scripts.run_evaluation --include-adversarial
Pop-Location
```

This updates evaluation/adversarial metrics consumed by the dashboard.

## Data Privacy and Security Design

- Prompts/outputs are treated as sensitive by default.
- Raw values are not persisted in audit logs.
- Entity references in logs are hash-based plus masked excerpts.
- Reversible mapping values are encrypted at rest.
- Admin features protected with signed session cookie and CSRF header.
- Public endpoints do not expose raw mapping data.
- Rate limiting throttles abusive request patterns.

## Limitations

- Transformer zero-shot inference may need additional runtime dependencies or model warm-up in constrained environments.
- SQLite is suitable for local/demo usage; production should use a managed DB.
- Local admin auth is intentionally simple and should be upgraded for production IAM.
- Training dataset included here is a seed set and should be expanded for production-grade coverage.

## Future Improvements

- Add pluggable NER backend with small multilingual model.
- Add role-based access control and audit retention policy controls.
- Add more robust transliteration and phonetic matching for Roman Urdu.
- Add end-to-end Playwright UI tests and CI pipeline automation.

## Methodology References

- Architecture: `docs/architecture.md`
- Data model: `docs/data-model.md`
- Privacy methodology: `docs/methodology.md`

## Screenshot Placeholders

- `docs/screenshots/landing.png`
- `docs/screenshots/dashboard.png`
- `docs/screenshots/live-shield.png`
- `docs/screenshots/adversarial-lab.png`
- `docs/screenshots/metrics.png`
- `docs/screenshots/audit-trail.png`

