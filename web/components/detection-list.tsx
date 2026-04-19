import type { Detection } from "@/lib/types";
import { StatusBadge } from "@/components/status-badge";

interface DetectionListProps {
  detections: Detection[];
}

export function DetectionList({ detections }: DetectionListProps) {
  if (detections.length === 0) {
    return (
      <div className="rounded-xl border border-dashed border-white/15 bg-white/[0.02] p-5 text-sm text-white/60">
        No sensitive entities detected in this request.
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-xl border border-white/10">
      <table className="w-full text-sm">
        <thead className="bg-white/5 text-left text-xs uppercase tracking-[0.14em] text-white/60">
          <tr>
            <th className="px-3 py-2">Type</th>
            <th className="px-3 py-2">Span</th>
            <th className="px-3 py-2">Confidence</th>
            <th className="px-3 py-2">Strategy</th>
            <th className="px-3 py-2">Replacement</th>
          </tr>
        </thead>
        <tbody>
          {detections.map((detection, index) => (
            <tr key={`${detection.start}-${detection.end}-${index}`} className="border-t border-white/10 text-white/85">
              <td className="px-3 py-2">
                <StatusBadge value={detection.entity_type} />
              </td>
              <td className="px-3 py-2 text-white/70">{detection.start} - {detection.end}</td>
              <td className="px-3 py-2">{Math.round(detection.confidence * 100)}%</td>
              <td className="px-3 py-2 text-white/70">{detection.strategy}</td>
              <td className="px-3 py-2 text-skyline">{detection.placeholder ?? "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
