"use client";
import { useMemo, useState } from "react";
import type { BasicBlock, Disassembly } from "@/lib/types";

// Block-terminator kind -> accent color (matches the HTML report).
const KIND_COLOR: Record<string, string> = {
  ret: "#c96868",
  jump: "#3987e5",
  cond: "#c98500",
  call: "#199e70",
  fallthrough: "#8b94a7",
};

function hex(n: number): string {
  return "0x" + Math.round(n).toString(16);
}

// Order blocks by address (they arrive sorted) and give each a row index so
// edges can be drawn as curves down the left gutter. A full graph layout is
// overkill for an entry-point CFG; a vertical stack with edge arcs reads
// clearly and never overlaps.
function useLayout(blocks: BasicBlock[]) {
  return useMemo(() => {
    const index = new Map<number, number>();
    blocks.forEach((b, i) => index.set(b.address, i));
    const edges: { from: number; to: number; back: boolean }[] = [];
    blocks.forEach((b, i) => {
      for (const s of b.successors) {
        const j = index.get(s);
        if (j !== undefined) edges.push({ from: i, to: j, back: j <= i });
      }
    });
    return { index, edges };
  }, [blocks]);
}

function Block({ block }: { block: BasicBlock }) {
  const color = KIND_COLOR[block.kind] ?? "#8b94a7";
  return (
    <div
      id={`blk-${block.address}`}
      className="card"
      style={{ borderLeft: `3px solid ${color}`, padding: "8px 10px", margin: 0 }}
    >
      <div
        className="mono small"
        style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}
      >
        <b>loc_{Math.round(block.address).toString(16)}</b>
        <span
          className="badge"
          style={{ borderColor: color, color }}
        >
          {block.kind}
        </span>
        {block.successors.length > 0 && (
          <span className="muted">→ {block.successors.map(hex).join(", ")}</span>
        )}
      </div>
      <div style={{ overflowX: "auto" }}>
        {block.instructions.map((ins, i) => (
          <div key={i} className="mono" style={{ fontSize: 12, whiteSpace: "nowrap" }}>
            <span style={{ color: "#6b7f9e", marginRight: 10 }}>
              {Math.round(ins.address).toString(16).padStart(8, "0")}
            </span>
            <span style={{ color: "#5b6472", marginRight: 10 }}>{ins.bytes_hex}</span>
            <span style={{ color: "#7c9cff", fontWeight: 600 }}>{ins.mnemonic}</span>{" "}
            <span>{ins.op_str}</span>
            {ins.comment && <span className="muted"> ; {ins.comment}</span>}
          </div>
        ))}
      </div>
    </div>
  );
}

export function CfgView({ dis }: { dis: Disassembly }) {
  const [showGraph, setShowGraph] = useState(true);
  const { edges } = useLayout(dis.blocks);

  if (!dis.available || dis.blocks.length === 0) {
    return (
      <p className="muted small">
        {dis.note || "No disassembly available."}
        {!dis.available && dis.note.includes("capstone") && (
          <> Install with <span className="mono">pip install capstone</span>.</>
        )}
      </p>
    );
  }

  const insns = dis.blocks.reduce((a, b) => a + b.instructions.length, 0);

  return (
    <div>
      <div
        className="small muted"
        style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 10 }}
      >
        <span>
          arch <b>{dis.arch}</b> · entry <span className="mono">{hex(dis.entry)}</span> ·{" "}
          {dis.blocks.length} blocks · {insns} instructions
          {dis.truncated && <b style={{ color: "#eab308" }}> · truncated (budget hit)</b>}
        </span>
        <button
          className="btn btn-ghost small"
          style={{ marginLeft: "auto", padding: "3px 10px" }}
          onClick={() => setShowGraph((g) => !g)}
        >
          {showGraph ? "Linear view" : "Graph view"}
        </button>
      </div>

      {showGraph ? (
        <CfgGraph blocks={dis.blocks} edges={edges} />
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {dis.blocks.map((b) => (
            <Block key={b.address} block={b} />
          ))}
        </div>
      )}
    </div>
  );
}

// The graph view: blocks stacked in a column with an SVG gutter on the left
// drawing arcs between predecessor/successor rows. Forward edges arc down the
// right of the gutter; back-edges (loops) arc down the left and are dashed.
function CfgGraph({
  blocks,
  edges,
}: {
  blocks: BasicBlock[];
  edges: { from: number; to: number; back: boolean }[];
}) {
  const ROW = 118; // nominal row height used for edge geometry
  const GUTTER = 48;
  const height = blocks.length * ROW;

  const y = (i: number) => i * ROW + 24;

  return (
    <div style={{ display: "flex", gap: 8 }}>
      <svg width={GUTTER} height={height} style={{ flex: "none", overflow: "visible" }}>
        {edges.map((e, i) => {
          const y1 = y(e.from);
          const y2 = y(e.to);
          const color = e.back ? "#c98500" : "#4a5568";
          const x = e.back ? 8 : GUTTER - 8;
          const bow = e.back ? -22 : 22;
          const d = `M ${GUTTER - 6} ${y1} C ${x + bow} ${y1}, ${x + bow} ${y2}, ${GUTTER - 6} ${y2}`;
          return (
            <g key={i}>
              <path
                d={d}
                fill="none"
                stroke={color}
                strokeWidth="1.5"
                strokeDasharray={e.back ? "4 3" : undefined}
                markerEnd="url(#arrow)"
              />
            </g>
          );
        })}
        <defs>
          <marker
            id="arrow"
            markerWidth="7"
            markerHeight="7"
            refX="5"
            refY="3"
            orient="auto"
          >
            <path d="M0 0 L6 3 L0 6 Z" fill="#4a5568" />
          </marker>
        </defs>
      </svg>

      <div style={{ display: "flex", flexDirection: "column", gap: 0, flex: 1, minWidth: 0 }}>
        {blocks.map((b, i) => (
          <div key={b.address} style={{ height: ROW, paddingBottom: 8 }}>
            <Block block={b} />
          </div>
        ))}
      </div>
    </div>
  );
}
