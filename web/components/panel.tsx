import { cn } from "@/lib/utils";

interface PanelProps {
  title?: string;
  subtitle?: string;
  className?: string;
  children: React.ReactNode;
  rightSlot?: React.ReactNode;
}

export function Panel({ title, subtitle, className, children, rightSlot }: PanelProps) {
  return (
    <section className={cn("rounded-2xl border border-white/10 bg-steel/60 p-4 shadow-glass", className)}>
      {(title || subtitle || rightSlot) && (
        <header className="mb-4 flex items-start justify-between gap-3">
          <div>
            {title && <h3 className="text-base font-semibold text-white">{title}</h3>}
            {subtitle && <p className="mt-1 text-sm text-white/60">{subtitle}</p>}
          </div>
          {rightSlot}
        </header>
      )}
      {children}
    </section>
  );
}
