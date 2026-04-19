"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { ArrowRight, ShieldAlert, Sparkles } from "lucide-react";

import { MetricCard } from "@/components/metric-card";
import { ModeComparisonChart } from "@/components/mode-comparison-chart";
import { Panel } from "@/components/panel";
import { StatusBadge } from "@/components/status-badge";
import { getDashboardMetrics, getWalkthrough } from "@/lib/api";
import type { DashboardMetrics } from "@/lib/types";

export default function DashboardPage() {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [walkthrough, setWalkthrough] = useState<Array<{ title: string; description: string }>>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    async function load() {
      setLoading(true);
      setError("");
      try {
        const [metricPayload, walkthroughPayload] = await Promise.all([getDashboardMetrics(), getWalkthrough()]);
        setMetrics(metricPayload);
        setWalkthrough(walkthroughPayload.steps);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load dashboard data");
      } finally {
        setLoading(false);
      }
    }

    load();
  }, []);

  const modeRows = useMemo(() => {
    if (!metrics) {
      return [];
    }
    return Object.entries(metrics.mode_comparison).map(([mode, value]) => ({
      mode,
      f1: Math.round(value.f1 * 100),
      leakage: Math.round(value.leakage_rate * 100),
      utility: Math.round(value.utility * 100)
    }));
  }, [metrics]);

  if (loading) {
    return <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-6 text-white/70">Loading dashboard telemetry...</div>;
  }

  if (!metrics) {
    return (
      <div className="rounded-2xl border border-rose-400/30 bg-rose-400/10 p-6 text-rose-200">
        {error || "Dashboard data unavailable."}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Total Events" value={metrics.total_events} />
        <MetricCard label="Active Sessions" value={metrics.active_sessions} />
        <MetricCard label="Average Risk" value={metrics.average_risk} variant="percent" />
        <MetricCard label="Leakage Rate" value={metrics.leakage_rate} variant="percent" />
      </section>

      <section className="grid gap-6 xl:grid-cols-[1.2fr_1fr]">
        <Panel
          title="Mode Comparison"
          subtitle="Privacy, utility, and leakage results across shielding strategies"
          rightSlot={<StatusBadge value="Evaluation-backed" tone="good" />}
        >
          <ModeComparisonChart modeComparison={metrics.mode_comparison} />
        </Panel>

        <Panel title="Demo Walkthrough" subtitle="Suggested capstone demo sequence">
          <ol className="space-y-3 text-sm text-white/80">
            {walkthrough.map((item, index) => (
              <li key={item.title} className="rounded-xl border border-white/10 bg-white/[0.03] p-3">
                <p className="text-xs uppercase tracking-[0.12em] text-skyline">Step {index + 1}</p>
                <p className="mt-1 font-medium text-white">{item.title}</p>
                <p className="mt-1 text-white/70">{item.description}</p>
              </li>
            ))}
          </ol>
        </Panel>
      </section>

      <section className="grid gap-6 lg:grid-cols-[1.1fr_1fr]">
        <Panel title="Recent Audit Activity" subtitle="Safe metadata only, no raw secrets stored">
          <div className="overflow-hidden rounded-xl border border-white/10">
            <table className="w-full text-sm">
              <thead className="bg-white/5 text-left text-xs uppercase tracking-[0.14em] text-white/60">
                <tr>
                  <th className="px-3 py-2">Type</th>
                  <th className="px-3 py-2">Mode</th>
                  <th className="px-3 py-2">Risk</th>
                  <th className="px-3 py-2">Latency</th>
                </tr>
              </thead>
              <tbody>
                {metrics.recent_events.slice(0, 8).map((event) => (
                  <tr key={event.id} className="border-t border-white/10 text-white/85">
                    <td className="px-3 py-2">{event.event_type}</td>
                    <td className="px-3 py-2 text-white/70">{event.mode}</td>
                    <td className="px-3 py-2">{Math.round(event.risk_score * 100)}%</td>
                    <td className="px-3 py-2">{event.latency_ms.toFixed(1)} ms</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel title="Launch Flows" subtitle="Move quickly through core user journeys">
          <div className="grid gap-3">
            <Link href="/shield" className="group rounded-xl border border-white/10 bg-white/[0.03] p-4 transition hover:bg-white/[0.06]">
              <p className="text-sm font-medium text-white">Live Prompt Shield</p>
              <p className="mt-1 text-sm text-white/70">Analyze and sanitize multilingual prompts in real time.</p>
              <p className="mt-2 inline-flex items-center gap-1 text-xs text-skyline">
                Open shield
                <ArrowRight className="h-3.5 w-3.5 transition group-hover:translate-x-0.5" />
              </p>
            </Link>
            <Link href="/adversarial" className="group rounded-xl border border-white/10 bg-white/[0.03] p-4 transition hover:bg-white/[0.06]">
              <p className="text-sm font-medium text-white">Adversarial Lab</p>
              <p className="mt-1 text-sm text-white/70">Run prompt injection and extraction resistance benchmarks.</p>
              <p className="mt-2 inline-flex items-center gap-1 text-xs text-amberline">
                Run suite
                <ArrowRight className="h-3.5 w-3.5 transition group-hover:translate-x-0.5" />
              </p>
            </Link>
            <div className="rounded-xl border border-skyline/20 bg-skyline/10 p-4 text-sm text-white/80">
              <p className="mb-1 inline-flex items-center gap-2 text-skyline">
                <Sparkles className="h-4 w-4" />
                Capstone tip
              </p>
              Present the privacy-utility tradeoff by comparing F1, leakage rate, and utility in the Metrics page.
            </div>
          </div>
        </Panel>
      </section>

      {error && (
        <div className="rounded-xl border border-amberline/30 bg-amberline/10 px-4 py-3 text-sm text-amberline">
          <ShieldAlert className="mr-2 inline h-4 w-4" />
          {error}
        </div>
      )}
    </div>
  );
}
