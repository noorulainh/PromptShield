"use client";

import { useEffect, useState } from "react";
import { BarChart3 } from "lucide-react";
import { toast } from "sonner";

import { LatencyChart } from "@/components/latency-chart";
import { MetricCard } from "@/components/metric-card";
import { Panel } from "@/components/panel";
import { StatusBadge } from "@/components/status-badge";
import { getDashboardMetrics, getSessionMetrics } from "@/lib/api";
import { findSessionIdByChatId, getActiveChatId, listChatSessions } from "@/lib/session";
import type { DashboardMetrics, SessionMetrics } from "@/lib/types";

export default function MetricsPage() {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [chatIdInput, setChatIdInput] = useState("001");
  const [sessionMetrics, setSessionMetrics] = useState<SessionMetrics | null>(null);
  const [sessionMetricsLoading, setSessionMetricsLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  async function loadMetrics() {
    setLoading(true);
    try {
      const payload = await getDashboardMetrics();
      setMetrics(payload);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to load metrics");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    const activeChatId = getActiveChatId() ?? "001";
    setChatIdInput(activeChatId);
    loadMetrics();
  }, []);

  async function loadSelectedChatMetrics(chatId: string) {
    const normalized = (chatId || "").trim();
    if (!normalized) {
      setSessionMetrics(null);
      return;
    }

    const sessionId = findSessionIdByChatId(normalized);
    if (!sessionId) {
      setSessionMetrics(null);
      return;
    }

    setSessionMetricsLoading(true);
    try {
      const payload = await getSessionMetrics(sessionId);
      setSessionMetrics(payload);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to load chat metrics");
      setSessionMetrics(null);
    } finally {
      setSessionMetricsLoading(false);
    }
  }

  useEffect(() => {
    loadSelectedChatMetrics(chatIdInput);
  }, [chatIdInput]);

  if (loading || !metrics) {
    return <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-6 text-white/70">Loading analytics...</div>;
  }
  const knownChats = listChatSessions();

  return (
    <div className="space-y-6">
      <section className="grid gap-4 md:grid-cols-3 xl:grid-cols-6">
        <MetricCard label="Active Sessions" value={metrics.active_sessions} />
        <MetricCard label="Total Events" value={metrics.total_events} />
        <MetricCard label="Blocked Rate" value={metrics.blocked_rate} variant="percent" />
        <MetricCard label="Leakage Rate" value={metrics.leakage_rate} variant="percent" />
        <MetricCard label="Average Latency" value={metrics.avg_latency_ms} variant="ms" />
        <MetricCard label="P95 Latency" value={metrics.p95_latency_ms} variant="ms" />
      </section>

      <Panel
        title="Chat-Specific Security Metrics"
        subtitle="Evaluate attack blocking, leakage, and usability impact for a specific chat ID"
        rightSlot={<StatusBadge value={`Selected chat: ${chatIdInput}`} tone="neutral" />}
      >
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <input
            value={chatIdInput}
            onChange={(event) => setChatIdInput(event.target.value.toUpperCase())}
            list="known-chat-ids"
            placeholder="001"
            className="w-32 rounded-lg border border-white/15 bg-ink/70 px-3 py-2 text-sm text-white outline-none"
          />
          <datalist id="known-chat-ids">
            {knownChats.map((item) => (
              <option key={item.chatId} value={item.chatId} />
            ))}
          </datalist>
          <button
            type="button"
            onClick={() => loadSelectedChatMetrics(chatIdInput)}
            className="rounded-lg border border-white/20 bg-white/5 px-3 py-2 text-xs text-white/80"
          >
            Refresh chat metrics
          </button>
        </div>

        {sessionMetricsLoading && <p className="text-sm text-white/65">Loading chat metrics...</p>}

        {!sessionMetricsLoading && !sessionMetrics?.has_activity && (
          <div className="rounded-xl border border-dashed border-white/15 bg-white/[0.02] p-4 text-sm text-white/65">
            No turns recorded yet for this chat ID. Start chatting to populate attack block rate, leakage rate, and usability impact.
          </div>
        )}

        {!sessionMetricsLoading && sessionMetrics?.has_activity && (
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
            <MetricCard label="Turns" value={sessionMetrics.total_turns} />
            <MetricCard label="Attack Block Rate" value={sessionMetrics.blocked_attack_rate} variant="percent" />
            <MetricCard label="Leakage Rate" value={sessionMetrics.leakage_rate} variant="percent" />
            <MetricCard label="Usability Impact" value={sessionMetrics.usability_impact} variant="percent" />
            <MetricCard label="Masked Utility" value={sessionMetrics.avg_masked_utility} variant="percent" />
          </div>
        )}
      </Panel>

      <section className="grid gap-6 lg:grid-cols-[1fr_1fr]">
        <Panel title="Latency Distribution" subtitle="Request processing performance profile">
          <LatencyChart avg={metrics.avg_latency_ms} p50={metrics.p50_latency_ms} p95={metrics.p95_latency_ms} />
        </Panel>

        <Panel title="Recent Label Mix" subtitle="Simple distribution across safe, pii, and injection decisions">
          <div className="grid gap-3 sm:grid-cols-3">
            <div className="rounded-xl border border-white/10 bg-white/[0.03] p-3 text-sm text-white/85">
              <p className="text-xs uppercase tracking-[0.08em] text-white/60">Safe</p>
              <p className="mt-1 text-lg font-semibold text-white">{metrics.label_distribution.safe ?? 0}</p>
            </div>
            <div className="rounded-xl border border-white/10 bg-white/[0.03] p-3 text-sm text-white/85">
              <p className="text-xs uppercase tracking-[0.08em] text-white/60">PII</p>
              <p className="mt-1 text-lg font-semibold text-white">{metrics.label_distribution.pii ?? 0}</p>
            </div>
            <div className="rounded-xl border border-white/10 bg-white/[0.03] p-3 text-sm text-white/85">
              <p className="text-xs uppercase tracking-[0.08em] text-white/60">Injection</p>
              <p className="mt-1 text-lg font-semibold text-white">{metrics.label_distribution.injection ?? 0}</p>
            </div>
          </div>
        </Panel>
      </section>

      <div className="rounded-xl border border-skyline/25 bg-skyline/10 p-4 text-sm text-white/85">
        <p className="inline-flex items-center gap-2 text-skyline">
          <BarChart3 className="h-4 w-4" />
          Evaluation dimensions
        </p>
        <p className="mt-2 text-white/70">
          Focus on security effectiveness (attack block rate + leakage rate), user experience cost (usability impact),
          and system responsiveness (average and p95 latency).
        </p>
      </div>
    </div>
  );
}
