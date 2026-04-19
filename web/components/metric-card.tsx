import { cn, formatMs, formatPercent } from "@/lib/utils";

interface MetricCardProps {
  label: string;
  value: number;
  variant?: "number" | "percent" | "ms";
  className?: string;
}

export function MetricCard({ label, value, variant = "number", className }: MetricCardProps) {
  const display =
    variant === "percent" ? formatPercent(value) : variant === "ms" ? formatMs(value) : value.toLocaleString();

  return (
    <div className={cn("rounded-xl border border-white/10 bg-white/[0.03] p-4", className)}>
      <p className="text-xs uppercase tracking-[0.14em] text-white/60">{label}</p>
      <p className="mt-2 text-2xl font-semibold text-white">{display}</p>
    </div>
  );
}
