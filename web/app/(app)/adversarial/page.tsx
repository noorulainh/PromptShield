"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, Loader2, ShieldCheck } from "lucide-react";
import { toast } from "sonner";

import { MetricCard } from "@/components/metric-card";
import { Panel } from "@/components/panel";
import { StatusBadge } from "@/components/status-badge";
import { getLatestAdversarial, runAdversarial } from "@/lib/api";
import type { AdversarialLatest, AdversarialRun, Mode } from "@/lib/types";

const MODE_OPTIONS: Mode[] = ["ml_based", "heuristic_based"];

export default function AdversarialPage() {
  const [mode, setMode] = useState<Mode>("ml_based");
  const [result, setResult] = useState<AdversarialRun | null>(null);
  const [latest, setLatest] = useState<AdversarialLatest | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    async function loadLatest() {
      try {
        const payload = await getLatestAdversarial();
        setLatest(payload);
        if (payload.results && payload.results.length > 0) {
          setResult({
            run_id: payload.run_id ?? "latest",
            mode: payload.mode ?? mode,
            total_cases: payload.total_cases,
            passed_cases: payload.passed_cases,
            leakage_rate: payload.leakage_rate,
            average_latency_ms: payload.average_latency_ms ?? 0,
            results: payload.results
          });
        }
      } catch {
        setLatest(null);
      }
    }
    loadLatest();
  }, []);

  async function handleRun() {
    setLoading(true);
    try {
      const payload = await runAdversarial(mode);
      setResult(payload);
      setLatest(payload);
      toast.success("Adversarial suite completed");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to run adversarial suite");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <Panel
        title="Adversarial Lab"
        subtitle="Prompt injection and exfiltration resistance benchmarking"
        rightSlot={<StatusBadge value="Dataset-backed tests" tone="warn" />}
      >
        <div className="mb-4 flex flex-wrap gap-2">
          {MODE_OPTIONS.map((option) => (
            <button
              key={option}
              type="button"
              onClick={() => setMode(option)}
              className={`rounded-lg border px-3 py-1.5 text-xs ${
                mode === option
                  ? "border-amberline/60 bg-amberline/20 text-white"
                  : "border-white/15 bg-white/5 text-white/75"
              }`}
            >
              {option}
            </button>
          ))}
        </div>

        <button
          type="button"
          onClick={handleRun}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-xl bg-amberline px-4 py-2 text-sm font-medium text-ink disabled:cursor-not-allowed disabled:opacity-70"
        >
          {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <AlertTriangle className="h-4 w-4" />}
          Run adversarial suite
        </button>
      </Panel>

      <section className="grid gap-4 md:grid-cols-3">
        <MetricCard label="Cases" value={(result?.total_cases ?? latest?.total_cases) || 0} />
        <MetricCard label="Passed" value={(result?.passed_cases ?? latest?.passed_cases) || 0} />
        <MetricCard label="Leakage Rate" value={(result?.leakage_rate ?? latest?.leakage_rate) || 0} variant="percent" />
      </section>

      <Panel title="Latest Results" subtitle="Each row is a concrete attack scenario with pass/fail outcome">
        {!result && (
          <div className="rounded-xl border border-dashed border-white/15 bg-white/[0.02] p-4 text-sm text-white/65">
            Run the suite to view detailed case-by-case outcomes.
          </div>
        )}

        {result && (
          <div className="space-y-3">
            {result.results.map((item) => (
              <details key={item.case_id} className="group overflow-hidden rounded-xl border border-white/10 bg-white/[0.03]">
                <summary className="flex cursor-pointer list-none flex-wrap items-center justify-between gap-3 px-4 py-3 text-sm text-white">
                  <div>
                    <p className="text-xs uppercase tracking-[0.12em] text-skyline">{item.case_id}</p>
                    <p className="mt-1 font-medium">{item.scenario}</p>
                    <p className="mt-1 text-xs text-white/60">Attack type: {item.attack_type}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-white/70">{item.latency_ms.toFixed(1)} ms</span>
                    {item.passed ? <StatusBadge value="PASS" tone="good" /> : <StatusBadge value="FAIL" tone="danger" />}
                  </div>
                </summary>

                <div className="grid gap-3 border-t border-white/10 p-4 text-sm text-white/80 lg:grid-cols-2">
                  <div className="space-y-2">
                    <p className="text-xs uppercase tracking-[0.12em] text-white/60">Input</p>
                    <p className="rounded-lg border border-white/10 bg-ink/60 p-2">{item.input_text}</p>
                    <p className="text-xs uppercase tracking-[0.12em] text-white/60">Sanitized Input</p>
                    <p className="rounded-lg border border-white/10 bg-ink/60 p-2">{item.sanitized_input}</p>
                    <p className="text-xs uppercase tracking-[0.12em] text-white/60">Attack Prompt</p>
                    <p className="rounded-lg border border-white/10 bg-ink/60 p-2">{item.attack_prompt}</p>
                  </div>

                  <div className="space-y-2">
                    <p className="text-xs uppercase tracking-[0.12em] text-white/60">Simulated Output</p>
                    <p className="rounded-lg border border-white/10 bg-ink/60 p-2">{item.simulated_output}</p>
                    <p className="text-xs uppercase tracking-[0.12em] text-white/60">Guarded Output</p>
                    <p className="rounded-lg border border-white/10 bg-ink/60 p-2">{item.guarded_output}</p>
                    <p className="text-xs uppercase tracking-[0.12em] text-white/60">Guard Reasoning</p>
                    <p className="rounded-lg border border-white/10 bg-ink/60 p-2">{item.guard_reasons.join("; ") || "No guard reasons"}</p>
                  </div>

                  <div className="rounded-lg border border-white/10 bg-white/[0.02] p-3">
                    <p className="mb-2 text-xs uppercase tracking-[0.12em] text-white/60">Input Detections ({item.input_detections.length})</p>
                    <div className="flex flex-wrap gap-2">
                      {item.input_detections.map((detection, idx) => (
                        <span key={`${item.case_id}-in-${idx}`} className="rounded-md border border-white/15 px-2 py-1 text-xs">
                          {detection.entity_type} · {Math.round(detection.confidence * 100)}%
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="rounded-lg border border-white/10 bg-white/[0.02] p-3">
                    <p className="mb-2 text-xs uppercase tracking-[0.12em] text-white/60">Output Detections ({item.output_detections.length})</p>
                    <div className="flex flex-wrap gap-2">
                      {item.output_detections.map((detection, idx) => (
                        <span key={`${item.case_id}-out-${idx}`} className="rounded-md border border-white/15 px-2 py-1 text-xs">
                          {detection.entity_type} · {Math.round(detection.confidence * 100)}%
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </details>
            ))}
          </div>
        )}
      </Panel>

      <div className="rounded-xl border border-pulse/20 bg-pulse/10 p-4 text-sm text-white/80">
        <p className="inline-flex items-center gap-2 text-pulse">
          <ShieldCheck className="h-4 w-4" />
          Attack coverage included
        </p>
        <ul className="mt-2 space-y-1 text-white/75">
          <li>Spaced and punctuation-separated IDs</li>
          <li>Mixed-script and Roman Urdu variations</li>
          <li>Prompt injection and context recovery attempts</li>
          <li>Leetspeak-style email obfuscation</li>
        </ul>
      </div>
    </div>
  );
}
