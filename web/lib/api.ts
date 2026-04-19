import type {
  AdversarialLatest,
  AdversarialRun,
  AppSettings,
  AuditLogResponse,
  DashboardMetrics,
  SessionMetrics,
  MappingItem,
  Mode,
  ProcessResponse
} from "@/lib/types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000/api/v1";

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {})
    },
    cache: "no-store"
  });

  if (!response.ok) {
    let message = `Request failed with ${response.status}`;
    try {
      const payload = await response.json();
      message = payload.detail ?? payload.message ?? message;
    } catch {
      const text = await response.text();
      if (text) {
        message = text;
      }
    }
    throw new Error(message);
  }

  return response.json() as Promise<T>;
}

export function getApiBase() {
  return API_BASE;
}

export function createSession() {
  return apiFetch<{ session_id: string }>("/shield/session/new", { method: "POST" });
}

export function processPrompt(payload: { text: string; session_id?: string | null; mode: Mode }) {
  return apiFetch<ProcessResponse>("/shield/process", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export function analyzePrompt(payload: { text: string; session_id?: string | null }) {
  return apiFetch<ProcessResponse>("/shield/analyze", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export function analyzeOutput(payload: { text: string; session_id?: string | null; strict?: boolean }) {
  return apiFetch<ProcessResponse>("/shield/output/analyze", {
    method: "POST",
    body: JSON.stringify(payload)
  });
}

export function simulateChat(payload: { text: string; session_id?: string | null }) {
  return apiFetch<{
    session_id: string;
    sanitized_prompt: string;
    model_response: string;
    blocked: boolean;
    input_blocked: boolean;
    output_blocked: boolean;
    predicted_label: "safe" | "injection" | "pii";
    confidence_score: number;
    language: string;
    final_action: "allow" | "mask" | "block";
    decision_source: string;
    reasoning: string[];
    pii_detected: boolean;
    warning: string | null;
    latency_ms: number;
  }>("/shield/chat/simulate", {
    method: "POST",
    body: JSON.stringify({ ...payload, mode: "ml_based" })
  });
}

export function runAdversarial(mode: Mode) {
  return apiFetch<AdversarialRun>("/adversarial/run", {
    method: "POST",
    body: JSON.stringify({ mode })
  });
}

export function getLatestAdversarial() {
  return apiFetch<AdversarialLatest>("/adversarial/latest");
}

export function getDashboardMetrics() {
  return apiFetch<DashboardMetrics>("/metrics/dashboard");
}

export function getSessionMetrics(sessionId: string) {
  return apiFetch<SessionMetrics>(`/metrics/session/${encodeURIComponent(sessionId)}`);
}

export function runEvaluation() {
  return apiFetch<{ mode_comparison: Record<string, unknown> }>("/metrics/evaluation/run", {
    method: "POST"
  });
}

export function getLatestEvaluation() {
  return apiFetch<{ mode_comparison: Record<string, unknown> }>("/metrics/evaluation/latest");
}

export function getAuditLogs(params: {
  predicted_label?: string;
  language?: string;
  final_action?: string;
  limit?: number;
  offset?: number;
}) {
  const query = new URLSearchParams();
  if (params.predicted_label) query.set("predicted_label", params.predicted_label);
  if (params.language) query.set("language", params.language);
  if (params.final_action) query.set("final_action", params.final_action);
  if (params.limit !== undefined) query.set("limit", String(params.limit));
  if (params.offset !== undefined) query.set("offset", String(params.offset));
  const suffix = query.toString() ? `?${query.toString()}` : "";
  return apiFetch<AuditLogResponse>(`/audit/logs${suffix}`);
}

export function clearAuditLogs() {
  return apiFetch<{
    deleted_events: number;
    deleted_detections: number;
    deleted_sanitized_outputs: number;
    deleted_mappings: number;
    deleted_sessions: number;
  }>(
    "/audit/logs",
    {
      method: "DELETE"
    }
  );
}

export function getDemoSamples() {
  return apiFetch<{ samples: Array<Record<string, string>> }>("/demo/samples");
}

export function getWalkthrough() {
  return apiFetch<{ steps: Array<{ title: string; description: string }> }>("/demo/walkthrough");
}

export function loginAdmin(password: string) {
  return apiFetch<{ authenticated: boolean; csrf_token: string | null }>("/admin/auth/login", {
    method: "POST",
    body: JSON.stringify({ password })
  });
}

export function logoutAdmin() {
  return apiFetch<{ authenticated: boolean }>("/admin/auth/logout", { method: "POST" });
}

export function adminMe() {
  return apiFetch<{ authenticated: boolean; role: string | null }>("/admin/auth/me");
}

export function getSettings() {
  return apiFetch<{ settings: AppSettings }>("/admin/settings");
}

export function updateSettings(settings: AppSettings, csrfToken: string) {
  return apiFetch<{ settings: AppSettings }>("/admin/settings", {
    method: "PUT",
    headers: {
      "x-csrf-token": csrfToken
    },
    body: JSON.stringify(settings)
  });
}

export function getMappings(sessionId: string, revealRaw = false) {
  const query = revealRaw ? "?reveal_raw=true" : "";
  return apiFetch<MappingItem[]>(`/admin/mappings/${sessionId}${query}`);
}

export function deleteMappings(sessionId: string, csrfToken: string) {
  return apiFetch<{ deleted: number }>(`/admin/mappings/${sessionId}`, {
    method: "DELETE",
    headers: {
      "x-csrf-token": csrfToken
    }
  });
}

export function listSessions() {
  return apiFetch<Array<{ session_id: string; created_at: string; last_seen: string; event_count: number }>>(
    "/admin/sessions"
  );
}
