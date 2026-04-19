# PromptShield Architecture

## High-Level Flow

1. User enters prompt in web UI.
2. Frontend calls FastAPI shield endpoint.
3. Backend detector extracts sensitive entities with confidence and strategy labels.
4. Sanitization mode applies:
   - detect only
   - redact
   - pseudonymize
   - combined (pseudonymize + secondary guard)
5. Safe event metadata is written to audit tables.
6. Sanitized prompt can be used for model simulation.
7. Output guard re-checks model response and redacts leakage.
8. Metrics and audit pages read aggregated safe telemetry.

## Components

### Frontend (`web/`)
- Landing page for value proposition and demo entry.
- Command-center dashboard pages:
  - Live Shield
  - Conversation
  - Adversarial Lab
  - Audit Trail
  - Metrics
  - Settings/Admin
  - About/Methodology
- Typed API client with cookie-based auth support.

### Backend (`api/`)
- Route layer (`app/api/routes`): endpoint orchestration.
- Services layer (`app/services`): detection, pseudonymization, evaluation, logging.
- Security layer (`app/core/security.py`): hashing, encryption, signed admin token.
- Data layer (`app/db/models.py`): sessions/events/detections/mappings/settings/results.

## Privacy Pipeline

- Detection uses hybrid regex + locale heuristics.
- Canonical normalization handles Urdu digits and obfuscation separators.
- Pseudonymizer uses deterministic per-session hash lookup.
- Mapping table stores encrypted raw value and stable placeholder.
- Event records store sanitized text and hashed fingerprints only.

## Security Controls

- Request rate limiting middleware.
- Password-protected admin auth (signed cookie).
- CSRF token required for mutating admin endpoints.
- No raw PII in audit exports.
- Secrets configured through env variables.

## Deployment Modes

- Local Docker Compose: web + api + sqlite volume.
- Local native mode: run backend and frontend separately.
