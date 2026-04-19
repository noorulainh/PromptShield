export type Mode = "ml_based" | "heuristic_based";

export type EntityType =
  | "PERSON"
  | "PHONE"
  | "EMAIL"
  | "NATIONAL_ID"
  | "FINANCIAL"
  | "ADDRESS"
  | "DATE_OF_BIRTH"
  | "ORGANIZATION"
  | "OTHER_SENSITIVE";

export interface Detection {
  entity_type: EntityType;
  start: number;
  end: number;
  matched_text: string;
  confidence: number;
  strategy: string;
  placeholder?: string | null;
}

export interface ProcessResponse {
  session_id: string;
  mode: Mode;
  sanitized_text: string;
  detections: Detection[];
  risk_score: number;
  utility_score: number;
  latency_ms: number;
  predicted_label: "safe" | "injection" | "pii";
  confidence_score: number;
  language: string;
  decision_source: string;
  final_action: "allow" | "mask" | "block";
  reasoning: string[];
  pii_detected: boolean;
  blocked?: boolean;
  message?: string | null;
}

export interface AdversarialResult {
  case_id: string;
  scenario: string;
  attack_type: string;
  mode: Mode;
  passed: boolean;
  latency_ms: number;
  leakage_detected: boolean;
  leakage_reason?: string | null;
  input_text: string;
  sanitized_input: string;
  attack_prompt: string;
  simulated_output: string;
  guarded_output: string;
  input_detections: Detection[];
  output_detections: Detection[];
  guard_reasons: string[];
  risk_score: number;
}

export interface AdversarialRun {
  run_id: string;
  mode: Mode;
  total_cases: number;
  passed_cases: number;
  leakage_rate: number;
  average_latency_ms: number;
  results: AdversarialResult[];
}

export interface AdversarialLatest {
  run_id?: string | null;
  mode?: Mode;
  total_cases: number;
  passed_cases: number;
  leakage_rate: number;
  average_latency_ms?: number;
  results?: AdversarialResult[];
}

export interface ModeMetrics {
  precision: number;
  recall: number;
  f1: number;
  false_positive_rate: number;
  utility: number;
  leakage_rate: number;
  avg_latency_ms: number;
  p50_latency_ms: number;
  p95_latency_ms: number;
  pseudonym_consistency: number;
}

export interface DashboardMetrics {
  total_events: number;
  active_sessions: number;
  average_risk: number;
  leakage_rate: number;
  blocked_rate: number;
  fallback_rate: number;
  unsafe_rate: number;
  avg_latency_ms: number;
  p50_latency_ms: number;
  p95_latency_ms: number;
  label_distribution: Record<string, number>;
  mode_comparison: Record<string, ModeMetrics>;
  recent_events: Array<{
    id: number;
    session_id: string;
    event_type: string;
    mode: string;
    risk_score: number;
    latency_ms: number;
    leakage_detected: boolean;
    summary: string;
    created_at: string;
  }>;
}

export interface SessionMetrics {
  session_id: string;
  has_activity: boolean;
  total_turns: number;
  blocked_attack_rate: number;
  leakage_rate: number;
  fallback_rate: number;
  avg_latency_ms: number;
  avg_masked_utility: number;
  usability_impact: number;
}

export interface AuditLogItem {
  id: number;
  session_id: string;
  event_type: string;
  mode: string;
  raw_input?: string | null;
  language?: string | null;
  predicted_label?: string | null;
  confidence_score?: number | null;
  pii_detected: boolean;
  final_action?: string | null;
  decision_source?: string | null;
  risk_score: number;
  latency_ms: number;
  leakage_detected: boolean;
  summary: string;
  sanitized_text: string;
  created_at: string;
}

export interface AuditLogResponse {
  total: number;
  items: AuditLogItem[];
}

export interface MappingItem {
  id: number;
  session_id: string;
  entity_type: string;
  placeholder: string;
  masked_preview: string;
  created_at: string;
}

export interface AppSettings {
  risk_threshold: number;
  default_mode: Mode;
  block_high_risk_output: boolean;
}
