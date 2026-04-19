"use client";

import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import type { ModeMetrics } from "@/lib/types";

interface Props {
  modeComparison: Record<string, ModeMetrics>;
}

export function ModeComparisonChart({ modeComparison }: Props) {
  const data = Object.entries(modeComparison).map(([mode, metrics]) => ({
    mode,
    f1: Number((metrics.f1 * 100).toFixed(2)),
    leakage: Number((metrics.leakage_rate * 100).toFixed(2)),
    utility: Number((metrics.utility * 100).toFixed(2))
  }));

  return (
    <div className="h-72 w-full">
      <ResponsiveContainer>
        <BarChart data={data}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
          <XAxis dataKey="mode" stroke="rgba(255,255,255,0.6)" />
          <YAxis stroke="rgba(255,255,255,0.6)" />
          <Tooltip
            contentStyle={{
              backgroundColor: "#0d1526",
              border: "1px solid rgba(255,255,255,0.12)",
              borderRadius: 12,
              color: "#fff"
            }}
          />
          <Bar dataKey="f1" fill="#30B2F8" radius={[5, 5, 0, 0]} />
          <Bar dataKey="utility" fill="#06D6A0" radius={[5, 5, 0, 0]} />
          <Bar dataKey="leakage" fill="#F2C14E" radius={[5, 5, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
