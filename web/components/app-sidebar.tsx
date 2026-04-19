"use client";

import type { Route } from "next";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ClipboardList, Gauge, MessageSquare, Radar, type LucideIcon } from "lucide-react";

import { cn } from "@/lib/utils";

const navItems: { href: Route; label: string; icon: LucideIcon }[] = [
  { href: "/conversation", label: "Chatbot", icon: MessageSquare },
  { href: "/audit", label: "Audit Trail", icon: ClipboardList },
  { href: "/metrics", label: "Metrics", icon: Gauge }
];

export function AppSidebar() {
  const pathname = usePathname();

  return (
    <aside className="hidden border-r border-white/10 bg-ink/80 px-4 py-6 backdrop-blur lg:block lg:w-72">
      <div className="rounded-2xl border border-skyline/25 bg-steel/70 p-4 shadow-neon">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-skyline/20 p-2 text-skyline">
            <Radar className="h-5 w-5" />
          </div>
          <div>
            <p className="text-xs uppercase tracking-[0.2em] text-skyline/80">PromptShield</p>
            <p className="text-sm text-white/80">Real-Time Privacy Guard</p>
          </div>
        </div>
      </div>

      <nav className="mt-8 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const active = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "group flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition-all",
                active
                  ? "bg-skyline/20 text-white shadow-glass"
                  : "text-white/70 hover:bg-white/5 hover:text-white"
              )}
            >
              <Icon className={cn("h-4 w-4", active ? "text-skyline" : "text-white/60 group-hover:text-skyline")} />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
