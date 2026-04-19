import { cn } from "@/lib/utils";

interface StatusBadgeProps {
  value: string;
  tone?: "neutral" | "good" | "warn" | "danger";
}

const toneClasses: Record<NonNullable<StatusBadgeProps["tone"]>, string> = {
  neutral: "border-white/20 bg-white/10 text-white/80",
  good: "border-pulse/40 bg-pulse/10 text-pulse",
  warn: "border-amberline/40 bg-amberline/10 text-amberline",
  danger: "border-rose-400/40 bg-rose-400/10 text-rose-300"
};

export function StatusBadge({ value, tone = "neutral" }: StatusBadgeProps) {
  return (
    <span className={cn("inline-flex rounded-full border px-2 py-0.5 text-xs font-medium", toneClasses[tone])}>{value}</span>
  );
}
