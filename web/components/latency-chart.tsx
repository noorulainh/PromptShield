"use client";

import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

interface Props {
  avg: number;
  p50: number;
  p95: number;
}

export function LatencyChart({ avg, p50, p95 }: Props) {
  const data = [
    { point: "P50", value: p50 },
    { point: "Average", value: avg },
    { point: "P95", value: p95 }
  ];

  return (
    <div className="h-64 w-full">
      <ResponsiveContainer>
        <AreaChart data={data}>
          <defs>
            <linearGradient id="latencyFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#30B2F8" stopOpacity={0.5} />
              <stop offset="95%" stopColor="#30B2F8" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.08)" />
          <XAxis dataKey="point" stroke="rgba(255,255,255,0.6)" />
          <YAxis stroke="rgba(255,255,255,0.6)" />
          <Tooltip
            contentStyle={{
              backgroundColor: "#0d1526",
              border: "1px solid rgba(255,255,255,0.12)",
              borderRadius: 12,
              color: "#fff"
            }}
          />
          <Area type="monotone" dataKey="value" stroke="#30B2F8" fillOpacity={1} fill="url(#latencyFill)" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
