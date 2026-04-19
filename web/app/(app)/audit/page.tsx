"use client";

import { useEffect, useMemo, useState } from "react";
import { Download, Loader2, Search, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { Panel } from "@/components/panel";
import { StatusBadge } from "@/components/status-badge";
import { clearAuditLogs, getApiBase, getAuditLogs } from "@/lib/api";
import { resetClientConversationState } from "@/lib/session";
import type { AuditLogItem } from "@/lib/types";

const LABEL_OPTIONS = ["safe", "pii", "injection"];
const LANGUAGE_OPTIONS = ["english", "urdu", "roman_urdu"];
const DECISION_OPTIONS = ["allow", "mask", "block"];

export default function AuditPage() {
  const [items, setItems] = useState<AuditLogItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);

  const [labelFilter, setLabelFilter] = useState("");
  const [languageFilter, setLanguageFilter] = useState("");
  const [decisionFilter, setDecisionFilter] = useState("");

  async function loadLogs() {
    setLoading(true);
    try {
      const payload = await getAuditLogs({
        predicted_label: labelFilter || undefined,
        language: languageFilter || undefined,
        final_action: decisionFilter || undefined,
        limit: 200,
        offset: 0
      });
      setItems(payload.items);
      setTotal(payload.total);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to load audit logs");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadLogs();
  }, []);

  const exportUrl = useMemo(() => {
    const params = new URLSearchParams();
    if (labelFilter) params.set("predicted_label", labelFilter);
    if (languageFilter) params.set("language", languageFilter);
    if (decisionFilter) params.set("final_action", decisionFilter);
    const suffix = params.toString() ? `?${params.toString()}` : "";
    return `${getApiBase()}/audit/export.csv${suffix}`;
  }, [labelFilter, languageFilter, decisionFilter]);

  async function handleClearLogs() {
    const shouldClear = window.confirm("Clear all audit logs? This action cannot be undone.");
    if (!shouldClear) {
      return;
    }

    setLoading(true);
    try {
      const result = await clearAuditLogs();
      resetClientConversationState();
      toast.success(`Cleared ${result.deleted_events} audit events.`);
      await loadLogs();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to clear audit logs");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <Panel
        title="Audit Trail"
        subtitle="Filter by label type, language type, and decision type"
        rightSlot={<StatusBadge value={`${total} events`} tone="neutral" />}
      >
        <div className="grid gap-3 md:grid-cols-3">
          <select
            value={labelFilter}
            onChange={(event) => setLabelFilter(event.target.value)}
            className="rounded-lg border border-white/15 bg-ink/70 px-3 py-2 text-sm text-white outline-none"
          >
            <option value="">All labels</option>
            {LABEL_OPTIONS.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>

          <select
            value={languageFilter}
            onChange={(event) => setLanguageFilter(event.target.value)}
            className="rounded-lg border border-white/15 bg-ink/70 px-3 py-2 text-sm text-white outline-none"
          >
            <option value="">All languages</option>
            {LANGUAGE_OPTIONS.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>

          <select
            value={decisionFilter}
            onChange={(event) => setDecisionFilter(event.target.value)}
            className="rounded-lg border border-white/15 bg-ink/70 px-3 py-2 text-sm text-white outline-none"
          >
            <option value="">All decisions</option>
            {DECISION_OPTIONS.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </div>

        <div className="mt-3 flex flex-wrap gap-2">
          <button
            type="button"
            onClick={loadLogs}
            className="inline-flex items-center gap-2 rounded-lg bg-skyline px-3 py-2 text-xs font-medium text-ink"
          >
            {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Search className="h-3.5 w-3.5" />}
            Apply filters
          </button>
          <a
            href={exportUrl}
            className="inline-flex items-center gap-2 rounded-lg border border-white/20 bg-white/5 px-3 py-2 text-xs text-white/80"
          >
            <Download className="h-3.5 w-3.5" />
            Export CSV
          </a>
          <button
            type="button"
            onClick={handleClearLogs}
            className="inline-flex items-center gap-2 rounded-lg border border-rose-400/40 bg-rose-400/10 px-3 py-2 text-xs text-rose-200"
          >
            <Trash2 className="h-3.5 w-3.5" />
            Clear logs
          </button>
        </div>
      </Panel>

      <Panel title="Event Log" subtitle="Only sanitized metadata is stored by design">
        <div className="overflow-hidden rounded-xl border border-white/10">
          <table className="w-full text-sm">
            <thead className="bg-white/5 text-left text-xs uppercase tracking-[0.12em] text-white/60">
              <tr>
                <th className="px-3 py-2">Timestamp</th>
                <th className="px-3 py-2">Input (PII-safe)</th>
                <th className="px-3 py-2">Language</th>
                <th className="px-3 py-2">Label</th>
                <th className="px-3 py-2">Confidence</th>
                <th className="px-3 py-2">PII</th>
                <th className="px-3 py-2">Decision</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id} className="border-t border-white/10 text-white/85">
                  <td className="px-3 py-2 text-white/70">{new Date(item.created_at).toLocaleString()}</td>
                  <td className="max-w-[260px] truncate px-3 py-2 text-white/70">{item.raw_input || "-"}</td>
                  <td className="px-3 py-2">{item.language || "-"}</td>
                  <td className="px-3 py-2">{item.predicted_label || "-"}</td>
                  <td className="px-3 py-2">
                    {item.confidence_score !== null && item.confidence_score !== undefined
                      ? `${Math.round(item.confidence_score * 100)}%`
                      : "-"}
                  </td>
                  <td className="px-3 py-2">{item.pii_detected ? "Detected" : "None"}</td>
                  <td className="px-3 py-2">{item.final_action || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {items.length === 0 && !loading && (
          <div className="mt-4 rounded-xl border border-dashed border-white/15 bg-white/[0.02] p-4 text-sm text-white/60">
            No audit entries match the current filter set.
          </div>
        )}
      </Panel>
    </div>
  );
}
