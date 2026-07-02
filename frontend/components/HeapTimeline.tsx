"use client";
import { useMemo, useState } from "react";
import type { HeapSample } from "@/lib/types";
import { humanBytes } from "@/lib/memory";

// Change-over-time, one measure -> an area+line chart. Single series, so no
// legend (the heading names it); recessive grid; annotated event markers are
// direct-labeled rather than dumped in a legend.
const W = 720;
const H = 220;
const PAD = { top: 18, right: 16, bottom: 30, left: 56 };
const SERIES = "#3987e5";

export function HeapTimeline({ samples }: { samples: HeapSample[] }) {
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);

  const geom = useMemo(() => {
    if (samples.length === 0) return null;
    const tMax = Math.max(...samples.map((s) => s.t_ms), 1);
    const cMax = Math.max(...samples.map((s) => s.committed), 1);
    const iw = W - PAD.left - PAD.right;
    const ih = H - PAD.top - PAD.bottom;
    const x = (t: number) => PAD.left + (t / tMax) * iw;
    const y = (c: number) => PAD.top + ih - (c / cMax) * ih;
    const pts = samples.map((s) => [x(s.t_ms), y(s.committed)] as const);
    const line = pts.map((p, i) => (i ? "L" : "M") + p[0] + " " + p[1]).join(" ");
    const area = `M ${pts[0][0]} ${PAD.top + ih} ` +
      pts.map((p) => `L ${p[0]} ${p[1]}`).join(" ") +
      ` L ${pts[pts.length - 1][0]} ${PAD.top + ih} Z`;
    // y gridlines at 0/25/50/75/100% of cMax.
    const grid = [0, 0.25, 0.5, 0.75, 1].map((f) => ({
      yv: cMax * f,
      py: y(cMax * f),
    }));
    return { x, y, pts, line, area, cMax, tMax, ih, grid };
  }, [samples]);

  if (!geom) return <p className="muted">No heap timeline captured.</p>;

  return (
    <div>
      <div
        style={{ position: "relative", overflowX: "auto" }}
        onMouseLeave={() => setHoverIdx(null)}
      >
        <svg
          viewBox={`0 0 ${W} ${H}`}
          width="100%"
          style={{ maxWidth: W, display: "block" }}
          role="img"
          aria-label="Committed heap memory over time"
        >
          <defs>
            <linearGradient id="heapfill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={SERIES} stopOpacity="0.35" />
              <stop offset="100%" stopColor={SERIES} stopOpacity="0.02" />
            </linearGradient>
          </defs>

          {/* recessive gridlines + y labels */}
          {geom.grid.map((g, i) => (
            <g key={i}>
              <line
                x1={PAD.left}
                x2={W - PAD.right}
                y1={g.py}
                y2={g.py}
                stroke="var(--line)"
                strokeWidth="1"
              />
              <text x={PAD.left - 8} y={g.py + 4} textAnchor="end" fontSize="10" fill="var(--mut)">
                {humanBytes(g.yv)}
              </text>
            </g>
          ))}

          <path d={geom.area} fill="url(#heapfill)" />
          <path d={geom.line} fill="none" stroke={SERIES} strokeWidth="2" />

          {/* event markers with direct labels */}
          {samples.map((s, i) => {
            const [px, py] = geom.pts[i];
            const active = hoverIdx === i;
            return (
              <g key={i}>
                {s.note && (
                  <text
                    x={px}
                    y={py - 10}
                    textAnchor={i === samples.length - 1 ? "end" : "middle"}
                    fontSize="9.5"
                    fill="var(--mut)"
                  >
                    {s.note}
                  </text>
                )}
                <circle
                  cx={px}
                  cy={py}
                  r={active ? 6 : 4}
                  fill={active ? "#fff" : SERIES}
                  stroke={SERIES}
                  strokeWidth="2"
                />
                {/* generous invisible hit target */}
                <rect
                  x={px - 18}
                  y={PAD.top}
                  width={36}
                  height={geom.ih}
                  fill="transparent"
                  onMouseEnter={() => setHoverIdx(i)}
                />
              </g>
            );
          })}

          {/* x axis labels */}
          {samples.map((s, i) => (
            <text
              key={i}
              x={geom.pts[i][0]}
              y={H - 10}
              textAnchor="middle"
              fontSize="10"
              fill="var(--mut)"
            >
              {s.t_ms}ms
            </text>
          ))}
        </svg>
      </div>

      <div className="card" style={{ marginTop: 8, minHeight: 38 }}>
        {hoverIdx !== null ? (
          <span className="small fade-in">
            <b>t = {samples[hoverIdx].t_ms} ms</b> · committed{" "}
            <b>{humanBytes(samples[hoverIdx].committed)}</b>
            {samples[hoverIdx].note && (
              <span className="muted"> — {samples[hoverIdx].note}</span>
            )}
          </span>
        ) : (
          <span className="muted small">
            Committed heap over execution. A staircase climbing to a large plateau is the
            signature of a bulk file-encryption working set.
          </span>
        )}
      </div>
    </div>
  );
}
