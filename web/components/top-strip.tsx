"use client";

import { Sparkles } from "lucide-react";

export function TopStrip() {
  return (
    <header className="mb-6 flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-white/10 bg-steel/50 px-4 py-3 backdrop-blur">
      <div>
        <p className="text-xs uppercase tracking-[0.2em] text-skyline/70">Command Center</p>
        <h1 className="text-lg font-semibold text-white">PromptShield Operations</h1>
      </div>

      <div className="flex items-center gap-2 text-xs">
        <span className="inline-flex items-center gap-1 rounded-full border border-pulse/30 bg-pulse/10 px-2.5 py-1 text-pulse">
          <Sparkles className="h-3.5 w-3.5" />
          Secure Demo Mode
        </span>
      </div>
    </header>
  );
}
