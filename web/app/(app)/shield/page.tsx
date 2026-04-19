"use client";

import { useEffect, useMemo, useState } from "react";
import { Loader2, ShieldAlert, Sparkles } from "lucide-react";
import { toast } from "sonner";

import { DetectionList } from "@/components/detection-list";
import { MetricCard } from "@/components/metric-card";
import { Panel } from "@/components/panel";
import { StatusBadge } from "@/components/status-badge";
import { analyzeOutput, createSession, getDemoSamples, processPrompt } from "@/lib/api";
import { getClientSessionId, setClientSessionId } from "@/lib/session";
import type { Mode, ProcessResponse } from "@/lib/types";

const MODES: Array<{ value: Mode; label: string; description: string }> = [
  {
    value: "ml_based",
    label: "ML-based",
    description: "Transformer-guided detection with heuristic safety guardrails"
  },
  {
    value: "heuristic_based",
    label: "Heuristic-based",
    description: "Rules-only detection and masking without ML classification"
  }
];

export default function ShieldPage() {
  const [mode, setMode] = useState<Mode>("ml_based");
  const [text, setText] = useState("");
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [result, setResult] = useState<ProcessResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [samples, setSamples] = useState<Array<{ id: string; title: string; prompt: string }>>([]);

  const [outputText, setOutputText] = useState("");
  const [outputResult, setOutputResult] = useState<ProcessResponse | null>(null);
  const [outputLoading, setOutputLoading] = useState(false);

  useEffect(() => {
    async function bootstrap() {
      try {
        const existing = getClientSessionId();
        if (existing) {
          setSessionId(existing);
        } else {
          const created = await createSession();
          setSessionId(created.session_id);
          setClientSessionId(created.session_id);
        }

        const samplePayload = await getDemoSamples();
        setSamples(samplePayload.samples.slice(0, 5) as Array<{ id: string; title: string; prompt: string }>);
      } catch (err) {
        toast.error(err instanceof Error ? err.message : "Failed to initialize session");
      }
    }

    bootstrap();
  }, []);

  const selectedModeMeta = useMemo(() => MODES.find((item) => item.value === mode), [mode]);

  async function handleAnalyze() {
    if (!text.trim()) {
      toast.error("Enter a prompt first.");
      return;
    }

    setLoading(true);
    try {
      const payload = await processPrompt({
        text,
        mode,
        session_id: sessionId
      });
      setResult(payload);
      setSessionId(payload.session_id);
      setClientSessionId(payload.session_id);
      toast.success("Prompt processed through PromptShield");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Processing failed");
    } finally {
      setLoading(false);
    }
  }

  async function handleOutputGuard() {
    if (!outputText.trim()) {
      toast.error("Provide simulated model output to analyze.");
      return;
    }

    setOutputLoading(true);
    try {
      const payload = await analyzeOutput({
        text: outputText,
        session_id: sessionId,
        strict: true
      });
      setOutputResult(payload);
      toast.success(payload.blocked ? "Output leakage blocked" : "Output deemed safe");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Output guard failed");
    } finally {
      setOutputLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <Panel
        title="Live Prompt Shield"
        subtitle="Detect and sanitize sensitive entities before any data leaves your boundary"
        rightSlot={<StatusBadge value={sessionId ? `Session ${sessionId.slice(0, 8)}...` : "Session pending"} tone="neutral" />}
      >
        <div className="grid gap-4 xl:grid-cols-[1.2fr_1fr]">
          <div className="space-y-4">
            <textarea
              value={text}
              onChange={(event) => setText(event.target.value)}
              rows={9}
              placeholder="Paste user prompt here..."
              className="w-full rounded-xl border border-white/15 bg-ink/70 p-3 text-sm text-white outline-none transition focus:border-skyline/60"
            />

            <div className="flex flex-wrap gap-2">
              {MODES.map((option) => (
                <button
                  key={option.value}
                  onClick={() => setMode(option.value)}
                  className={`rounded-lg border px-3 py-1.5 text-xs transition ${
                    mode === option.value
                      ? "border-skyline/60 bg-skyline/20 text-white"
                      : "border-white/15 bg-white/5 text-white/75 hover:text-white"
                  }`}
                  type="button"
                >
                  {option.label}
                </button>
              ))}
            </div>

            <button
              onClick={handleAnalyze}
              disabled={loading}
              className="inline-flex items-center gap-2 rounded-xl bg-skyline px-4 py-2 text-sm font-medium text-ink transition hover:bg-skyline/90 disabled:cursor-not-allowed disabled:opacity-70"
              type="button"
            >
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              Run Shield
            </button>
          </div>

          <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4 text-sm">
            <p className="text-xs uppercase tracking-[0.14em] text-skyline">Selected mode</p>
            <h4 className="mt-2 text-lg font-semibold text-white">{selectedModeMeta?.label}</h4>
            <p className="mt-2 text-white/70">{selectedModeMeta?.description}</p>

            <p className="mt-5 text-xs uppercase tracking-[0.14em] text-white/50">Demo prompts</p>
            <div className="mt-2 space-y-2">
              {samples.map((sample) => (
                <button
                  key={sample.id}
                  type="button"
                  onClick={() => setText(sample.prompt)}
                  className="w-full rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-left text-xs text-white/80 transition hover:bg-white/[0.06]"
                >
                  {sample.title}
                </button>
              ))}
            </div>
          </div>
        </div>
      </Panel>

      <section className="grid gap-4 md:grid-cols-3">
        <MetricCard label="Risk score" value={result?.risk_score ?? 0} variant="percent" />
        <MetricCard label="Utility score" value={result?.utility_score ?? 0} variant="percent" />
        <MetricCard label="Latency" value={result?.latency_ms ?? 0} variant="ms" />
      </section>

      <Panel title="Sanitized Prompt" subtitle="This is what would be sent to the LLM after privacy guarding">
        <div className="rounded-xl border border-white/10 bg-ink/70 p-4 text-sm text-white/85">
          {result?.sanitized_text || "Run the shield to generate sanitized output."}
        </div>
      </Panel>

      <Panel title="Detected Entities" subtitle="Confidence-scored extraction across regex, locale, and heuristic strategies">
        <DetectionList detections={result?.detections ?? []} />
      </Panel>

      <Panel title="Model Output Guard" subtitle="Analyze and filter accidental leakage in model responses">
        <div className="grid gap-4 xl:grid-cols-[1.2fr_1fr]">
          <div className="space-y-3">
            <textarea
              value={outputText}
              onChange={(event) => setOutputText(event.target.value)}
              rows={5}
              placeholder="Paste simulated model output..."
              className="w-full rounded-xl border border-white/15 bg-ink/70 p-3 text-sm text-white outline-none transition focus:border-pulse/60"
            />
            <button
              type="button"
              onClick={handleOutputGuard}
              disabled={outputLoading}
              className="inline-flex items-center gap-2 rounded-xl bg-pulse px-4 py-2 text-sm font-medium text-ink transition hover:bg-pulse/90 disabled:cursor-not-allowed disabled:opacity-70"
            >
              {outputLoading && <Loader2 className="h-4 w-4 animate-spin" />}
              Analyze output
            </button>
          </div>

          <div className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
            <p className="text-xs uppercase tracking-[0.14em] text-white/60">Guarded output</p>
            <p className="mt-2 text-sm text-white/80">{outputResult?.sanitized_text || "No output processed yet."}</p>
            {outputResult?.message && <p className="mt-3 text-xs text-white/65">{outputResult.message}</p>}
            {outputResult?.blocked && (
              <p className="mt-4 inline-flex items-center gap-1 text-xs text-amberline">
                <ShieldAlert className="h-3.5 w-3.5" />
                Sensitive output blocked
              </p>
            )}
          </div>
        </div>
      </Panel>

      {!result && (
        <div className="rounded-xl border border-dashed border-skyline/25 bg-skyline/5 px-4 py-3 text-sm text-skyline">
          <Sparkles className="mr-2 inline h-4 w-4" />
          Tip: Start with ML-based mode, then compare against heuristic mode on the same prompt.
        </div>
      )}
    </div>
  );
}
