"use client";

import { useEffect, useState } from "react";
import { AlertTriangle, Loader2, Send, ShieldAlert } from "lucide-react";
import { toast } from "sonner";

import { Panel } from "@/components/panel";
import { StatusBadge } from "@/components/status-badge";
import { createSession, simulateChat } from "@/lib/api";
import {
  getClientSessionId,
  initializeChatSession,
  setClientSessionId,
  startFreshChatSession
} from "@/lib/session";

interface ChatMessage {
  id: string;
  role: "user" | "assistant";
  text: string;
  maskedText?: string;
  latencyMs?: number;
  details?: {
    language: string;
    predictedLabel: "safe" | "injection" | "pii";
    confidence: number;
    finalAction: "allow" | "mask" | "block";
    decisionSource: string;
    piiDetected: boolean;
    warning?: string | null;
  };
}

export default function ConversationPage() {
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [chatId, setChatId] = useState("001");
  const [input, setInput] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [loading, setLoading] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [inlineWarning, setInlineWarning] = useState<string | null>(null);

  useEffect(() => {
    async function bootstrap() {
      try {
        const existing = getClientSessionId();
        if (existing) {
          setSessionId(existing);
          setChatId(initializeChatSession(existing));
        } else {
          const created = await createSession();
          setSessionId(created.session_id);
          setClientSessionId(created.session_id);
          setChatId(initializeChatSession(created.session_id));
        }
      } catch (err) {
        toast.error(err instanceof Error ? err.message : "Failed to initialize conversation session");
      }
    }

    bootstrap();
  }, []);

  const canSend = input.trim().length > 0 && !loading && !clearing;

  async function handleClearChat() {
    setClearing(true);
    try {
      const created = await createSession();
      setSessionId(created.session_id);
      setClientSessionId(created.session_id);
      const nextChatId = startFreshChatSession(created.session_id);
      setChatId(nextChatId);
      setMessages([]);
      setInput("");
      setInlineWarning(null);
      toast.success(`Started fresh chat ${nextChatId}. Audit logs remain intact.`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to clear chat");
    } finally {
      setClearing(false);
    }
  }

  async function handleSend() {
    if (!canSend) {
      return;
    }
    setLoading(true);

    try {
      const payload = await simulateChat({
        text: input,
        session_id: sessionId
      });

      setSessionId(payload.session_id);
      setClientSessionId(payload.session_id);

      setMessages((previous) => [
        ...previous,
        {
          id: `${Date.now()}-u`,
          role: "user",
          text: input,
          maskedText: payload.sanitized_prompt,
          latencyMs: payload.latency_ms,
          details: {
            language: payload.language,
            predictedLabel: payload.predicted_label,
            confidence: payload.confidence_score,
            finalAction: payload.final_action,
            decisionSource: payload.decision_source,
            piiDetected: payload.pii_detected,
            warning: payload.warning
          }
        },
        {
          id: `${Date.now()}-a`,
          role: "assistant",
          text: payload.model_response,
          latencyMs: payload.latency_ms
        }
      ]);

      setInput("");
      setInlineWarning(payload.warning);

      if (payload.input_blocked) {
        toast.warning("Unsafe prompt injection attempt blocked.");
      } else if (payload.output_blocked) {
        toast.warning("Sensitive model output detected and masked.");
      } else if (payload.final_action === "mask") {
        toast.success("PII detected and masked before model response.");
      } else {
        toast.success("Conversation turn processed safely.");
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Conversation request failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <Panel
        title="Real-Time Secure Chatbot"
        subtitle="Always running in ML-based mode with heuristic guardrails"
        rightSlot={
          <div className="flex items-center gap-2">
            <StatusBadge value={`Chat ${chatId}`} tone="neutral" />
            <StatusBadge value="Mode: ML-based" tone="good" />
            <StatusBadge value={sessionId ? `Session ${sessionId.slice(0, 8)}...` : "Session pending"} tone="neutral" />
          </div>
        }
      >
        {inlineWarning && (
          <div className="mb-4 rounded-xl border border-amberline/30 bg-amberline/10 p-3 text-sm text-amberline">
            <p className="inline-flex items-center gap-2 font-medium">
              <AlertTriangle className="h-4 w-4" />
              Inline Warning
            </p>
            <p className="mt-1 text-white/85">{inlineWarning}</p>
          </div>
        )}

        <div className="space-y-3">
          {messages.length === 0 && (
            <div className="rounded-xl border border-dashed border-white/15 bg-white/[0.02] p-4 text-sm text-white/60">
              Start chatting. Unsafe injections are blocked and sensitive data is masked before response generation.
            </div>
          )}

          {messages.map((message) => (
            <div
              key={message.id}
              className={`rounded-xl border p-3 text-sm ${
                message.role === "user"
                  ? "border-skyline/30 bg-skyline/10 text-white"
                  : "border-pulse/30 bg-pulse/10 text-white"
              }`}
            >
              <p className="mb-1 text-xs uppercase tracking-[0.12em] text-white/60">
                {message.role === "assistant" ? "assistant (guarded output)" : message.role}
              </p>
              <p className="text-white/90">{message.text}</p>

              {message.maskedText && message.maskedText !== message.text && (
                <div className="mt-2 rounded-lg border border-white/15 bg-white/[0.03] p-2 text-xs text-white/75">
                  <p className="uppercase tracking-[0.08em] text-skyline/80">Masked prompt sent to model</p>
                  <p className="mt-1 text-white/85">{message.maskedText}</p>
                </div>
              )}

              {message.details && (
                <div className="mt-3 grid gap-2 text-xs text-white/75 md:grid-cols-3">
                  <p>Language: {message.details.language}</p>
                  <p>Label: {message.details.predictedLabel}</p>
                  <p>Confidence: {Math.round(message.details.confidence * 100)}%</p>
                  <p>Action: {message.details.finalAction}</p>
                  <p>PII detected: {message.details.piiDetected ? "yes" : "no"}</p>
                  <p>Source: {message.details.decisionSource}</p>
                </div>
              )}

              {message.details?.warning && (
                <p className="mt-2 inline-flex items-center gap-1 text-xs text-amberline">
                  <ShieldAlert className="h-3.5 w-3.5" />
                  {message.details.warning}
                </p>
              )}

              {message.latencyMs !== undefined && (
                <p className="mt-2 text-xs text-white/60">Latency: {message.latencyMs.toFixed(1)} ms</p>
              )}
            </div>
          ))}
        </div>

        <div className="mt-5 space-y-3">
          <textarea
            value={input}
            onChange={(event) => setInput(event.target.value)}
            rows={4}
            placeholder="Type a message, or try an injection attempt to test blocking behavior..."
            className="w-full rounded-xl border border-white/15 bg-ink/70 p-3 text-sm text-white outline-none focus:border-skyline/60"
          />
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={handleSend}
              disabled={!canSend}
              className="inline-flex items-center gap-2 rounded-xl bg-skyline px-4 py-2 text-sm font-medium text-ink disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}
              Send
            </button>
            <button
              type="button"
              onClick={handleClearChat}
              disabled={clearing}
              className="inline-flex items-center gap-2 rounded-xl border border-white/20 bg-white/5 px-4 py-2 text-sm text-white/80 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {clearing ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
              Clear chat (new ID)
            </button>
          </div>
        </div>
      </Panel>
    </div>
  );
}
