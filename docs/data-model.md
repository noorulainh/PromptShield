# PromptShield Data Model

## Tables

### `sessions`
- `id` (PK): session identifier used for conversational consistency.
- `client_hash`: hashed client fingerprint.
- `created_at`, `last_seen`.

### `events`
- `id` (PK)
- `session_id` (FK -> sessions.id)
- `event_type`: `prompt_process`, `output_guard`, `conversation_turn`, etc.
- `mode`: detect/redact/pseudonymize/combined
- `risk_score`, `latency_ms`, `utility_score`
- `leakage_detected`
- `request_fingerprint`: HMAC hash of normalized request payload
- `summary`, `sanitized_text`
- `created_at`

### `detections`
- `id` (PK)
- `event_id` (FK -> events.id)
- `session_id` (FK -> sessions.id)
- `entity_type`
- `start_idx`, `end_idx`
- `confidence`, `strategy`
- `normalized_hash`
- `placeholder` (if pseudonymized)
- `excerpt` (masked preview)
- `created_at`

### `sanitized_outputs`
- `id` (PK)
- `session_id` (FK)
- `direction`: `input` or `output`
- `original_hash`
- `sanitized_text`
- `created_at`

### `encrypted_mappings`
- `id` (PK)
- `session_id` (FK)
- `entity_type`
- `raw_hash` (session-scoped deterministic key)
- `encrypted_value` (Fernet)
- `placeholder`
- `created_at`, `updated_at`
- Unique: `(session_id, raw_hash)`

### `test_results`
- `id` (PK)
- `suite_name`: `evaluation` or `adversarial`
- `case_id`
- `mode`
- `passed`
- `leakage_rate`
- `latency_ms`
- `metrics_json`
- `created_at`

### `settings`
- `key` (PK)
- `value_json`
- `updated_at`

## Notes

- Raw prompt/output content is never stored in plain logs.
- Reversible mapping is encrypted and only retrievable through admin-protected routes.
- Metrics are persisted through settings snapshots and test result records.
