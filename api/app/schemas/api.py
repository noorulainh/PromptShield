from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

EntityType = Literal[
    "PERSON",
    "PHONE",
    "EMAIL",
    "NATIONAL_ID",
    "FINANCIAL",
    "ADDRESS",
    "DATE_OF_BIRTH",
    "ORGANIZATION",
    "OTHER_SENSITIVE",
]
ModeType = Literal["ml_based", "heuristic_based"]
PredictionLabel = Literal["safe", "injection", "pii"]
ActionType = Literal["allow", "mask", "block"]


class TextRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=8000)
    session_id: str | None = Field(default=None, max_length=64)
    language_hint: str | None = Field(default=None, max_length=32)

    @field_validator("text")
    @classmethod
    def trim_text(cls, value: str) -> str:
        return value.strip()


class ProcessRequest(TextRequest):
    mode: ModeType = "ml_based"


class DetectionOut(BaseModel):
    entity_type: EntityType
    start: int
    end: int
    matched_text: str
    confidence: float
    strategy: str
    placeholder: str | None = None


class ProcessResponse(BaseModel):
    session_id: str
    mode: ModeType
    sanitized_text: str
    detections: list[DetectionOut]
    risk_score: float
    utility_score: float
    latency_ms: float
    predicted_label: PredictionLabel
    confidence_score: float
    language: str
    decision_source: str
    final_action: ActionType
    reasoning: list[str] = Field(default_factory=list)
    pii_detected: bool = False
    blocked: bool = False
    message: str | None = None


class OutputGuardRequest(TextRequest):
    strict: bool = True


class AdversarialRunRequest(BaseModel):
    mode: ModeType = "ml_based"


class AdversarialCaseResult(BaseModel):
    case_id: str
    scenario: str
    attack_type: str
    mode: ModeType
    passed: bool
    latency_ms: float
    leakage_detected: bool
    leakage_reason: str | None = None
    input_text: str
    sanitized_input: str
    attack_prompt: str
    simulated_output: str
    guarded_output: str
    input_detections: list[DetectionOut]
    output_detections: list[DetectionOut]
    guard_reasons: list[str]
    risk_score: float


class AdversarialRunResponse(BaseModel):
    run_id: str
    mode: ModeType
    total_cases: int
    passed_cases: int
    leakage_rate: float
    average_latency_ms: float
    results: list[AdversarialCaseResult]


class ModeMetrics(BaseModel):
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    utility: float
    leakage_rate: float
    avg_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    pseudonym_consistency: float


class DashboardMetrics(BaseModel):
    total_events: int
    active_sessions: int
    average_risk: float
    leakage_rate: float
    blocked_rate: float
    fallback_rate: float
    unsafe_rate: float
    avg_latency_ms: float
    p50_latency_ms: float
    p95_latency_ms: float
    label_distribution: dict[str, int]
    mode_comparison: dict[str, ModeMetrics]
    recent_events: list[dict]


class SessionMetrics(BaseModel):
    session_id: str
    has_activity: bool
    total_turns: int
    blocked_attack_rate: float
    leakage_rate: float
    fallback_rate: float
    avg_latency_ms: float
    avg_masked_utility: float
    usability_impact: float


class AuditLogItem(BaseModel):
    id: int
    session_id: str
    event_type: str
    mode: str
    raw_input: str | None
    language: str | None
    predicted_label: str | None
    confidence_score: float | None
    pii_detected: bool
    final_action: str | None
    decision_source: str | None
    risk_score: float
    latency_ms: float
    leakage_detected: bool
    summary: str | None
    sanitized_text: str
    created_at: datetime


class AuditLogResponse(BaseModel):
    total: int
    items: list[AuditLogItem]


class MappingItem(BaseModel):
    id: int
    session_id: str
    entity_type: str
    placeholder: str
    masked_preview: str
    created_at: datetime


class SettingsPayload(BaseModel):
    risk_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    default_mode: ModeType = "ml_based"
    block_high_risk_output: bool = True


class SettingsResponse(BaseModel):
    settings: SettingsPayload


class LoginRequest(BaseModel):
    password: str = Field(..., min_length=4, max_length=128)


class LoginResponse(BaseModel):
    authenticated: bool
    csrf_token: str | None = None


class AuthStatus(BaseModel):
    authenticated: bool
    role: str | None = None
