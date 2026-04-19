# PromptShield Methodology

## 1) Multilingual Detection

PromptShield combines deterministic rules and contextual heuristics:

- Regex detections for high-confidence IDs (email, CNIC, phone, IBAN, etc.).
- Locale-aware context patterns (`dob`, `تاریخ پیدائش`, `mera naam`, etc.).
- Urdu digit normalization and separator-insensitive matching for obfuscation.
- Prompt-injection phrase detection for exfiltration intent.

This hybrid approach keeps runtime local, fast, and transparent for capstone demonstration.

## 2) Conversation-Consistent Pseudonymization

For each detected entity in a session:

1. Normalize/canonicalize entity text.
2. Generate session-scoped hash key.
3. Lookup or create mapping record.
4. Replace with deterministic placeholder (`[PERSON_1]`, `[PHONE_1]`).

This preserves semantic continuity while hiding raw values.

## 3) Adversarial Exfiltration Testing

Dataset includes attacks such as:

- Spaced/punctuated identifiers.
- Mixed script content (Urdu + Roman Urdu).
- Leetspeak obfuscation.
- Prompt injection recovery attempts.

Each case is evaluated for leakage after output guard processing.

## 4) Privacy-Utility Tradeoff Analysis

Per mode (`detect_only`, `redact`, `pseudonymize`, `combined`) we compute:

- Precision / Recall / F1
- False Positive Rate
- Leakage Rate
- Utility score (string similarity)
- Avg / P50 / P95 latency
- Pseudonym consistency

These metrics support a realistic systems-level discussion, not just model-level claims.

## 5) Secure Logging

- Persist safe metadata only.
- Fingerprint requests via keyed hash.
- Store masked excerpts instead of raw values.
- Encrypt reversible mapping payloads.
- Restrict mapping visibility to admin-protected endpoints with CSRF-safe mutations.
