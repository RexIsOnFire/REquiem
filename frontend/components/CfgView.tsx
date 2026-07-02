"use client";
import { useMemo, useState } from "react";
import type { BasicBlock, Disassembly, FunctionCfg } from "@/lib/types";

// Block-terminator kind -> accent color (matches the HTML report).
const KIND_COLOR: Record<string, string> = {
  ret: "#c96868",
  jump: "#3987e5",
  cond: "#c98500",
  call: "#199e70",
  fallthrough: "#8b94a7",
};

const SOURCE_LABEL: Record<string, string> = {
  entry: "entry",
  export: "export",
  symbol: "symbol",
  call: "discovered",
};

function hex(n: number): string {
  return "0x" + Math.round(n).toString(16);
}

function Block({ block }: { block: BasicBlock }) {
  const color = KIND_COLOR[block.kind] ?? "#8b94a7";
  return (
    <div
      className="card"
      style={{ borderLeft: `3px solid ${color}`, padding: "8px 10px", margin: 0 }}
    >
      <div
        className="mono small"
        style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}
      >
        <b>loc_{Math.round(block.address).toString(16)}</b>
        <span className="badge" style={{ borderColor: color, color }}>
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

function FunctionList({
  functions,
  selected,
  onSelect,
}: {
  functions: FunctionCfg[];
  selected: number;
  onSelect: (addr: number) => void;
}) {
  const [q, setQ] = useState("");
  const filtered = useMemo(() => {
    const needle = q.toLowerCase();
    return functions.filter(
      (f) => !needle || f.name.toLowerCase().includes(needle) || hex(f.address).includes(needle),
    );
  }, [functions, q]);

  return (
    <div
      className="card"
      style={{ padding: 8, width: 232, flex: "none", alignSelf: "flex-start", maxHeight: 520, display: "flex", flexDirection: "column" }}
    >
      <input
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder={`Filter ${functions.length} functions…`}
        className="mono"
        style={{
          background: "var(--panel2)",
          border: "1px solid var(--line)",
          borderRadius: 6,
          color: "var(--tx)",
          padding: "6px 8px",
          fontSize: 12,
          marginBottom: 6,
        }}
      />
      <div style={{ overflowY: "auto" }}>
        {filtered.map((f) => {
          const active = f.address === selected;
          return (
            <button
              key={f.address}
              onClick={() => onSelect(f.address)}
              className="mono"
              style={{
                display: "block",
                width: "100%",
                textAlign: "left",
                background: active ? "var(--panel2)" : "transparent",
                border: "none",
                borderLeft: `3px solid ${active ? "var(--accent)" : "transparent"}`,
                color: "var(--tx)",
                padding: "5px 8px",
                fontSize: 12,
                cursor: "pointer",
                borderRadius: 4,
              }}
            >
              <div
                style={{
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {f.name}
              </div>
              <div className="muted" style={{ fontSize: 10.5 }}>
                {hex(f.address)} · {SOURCE_LABEL[f.source] ?? f.source}
              </div>
            </button>
          );
        })}
        {filtered.length === 0 && (
          <div className="muted small" style={{ padding: 8 }}>
            no match
          </div>
        )}
      </div>
    </div>
  );
}

export function CfgView({ dis }: { dis: Disassembly }) {
  const functions = dis.functions ?? [];
  const [selectedAddr, setSelectedAddr] = useState<number>(
    functions[0]?.address ?? dis.entry,
  );
  const [showGraph, setShowGraph] = useState(true);

  if (!dis.available || functions.length === 0) {
    return (
      <p className="muted small">
        {dis.note || "No disassembly available."}
        {!dis.available && dis.note.includes("capstone") && (
          <> Install with <span className="mono">pip install capstone</span>.</>
        )}
      </p>
    );
  }

  const current =
    functions.find((f) => f.address === selectedAddr) ?? functions[0];
  const named = functions.filter((f) => f.source === "export" || f.source === "symbol").length;
  const totalInsns = functions.reduce(
    (a, f) => a + f.blocks.reduce((s, b) => s + b.instructions.length, 0),
    0,
  );

  return (
    <div>
      <div className="small muted" style={{ marginBottom: 10 }}>
        arch <b>{dis.arch}</b> · entry <span className="mono">{hex(dis.entry)}</span> ·{" "}
        {functions.length} functions ({named} named) · {totalInsns} instructions
        {dis.truncated && <b style={{ color: "#eab308" }}> · truncated (budget hit)</b>}
      </div>

      <div style={{ display: "flex", gap: 14, alignItems: "flex-start" }}>
        <FunctionList
          functions={functions}
          selected={current.address}
          onSelect={setSelectedAddr}
        />

        <div style={{ flex: 1, minWidth: 0 }}>
          <div
            style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10 }}
          >
            <b className="mono">{current.name}</b>
            <span className="muted mono small">
              {hex(current.address)} · {current.blocks.length} blocks
            </span>
            {current.truncated && (
              <span className="badge" style={{ color: "#eab308" }}>
                truncated
              </span>
            )}
            <button
              className="btn btn-ghost small"
              style={{ marginLeft: "auto", padding: "3px 10px" }}
              onClick={() => setShowGraph((g) => !g)}
            >
              {showGraph ? "Linear view" : "Graph view"}
            </button>
          </div>

          {showGraph ? (
            <CfgGraph key={current.address} blocks={current.blocks} />
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {current.blocks.map((b) => (
                <Block key={b.address} block={b} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// Graph view: blocks stacked in a column with an SVG gutter drawing arcs
// between predecessor/successor rows. Forward edges arc down the right of the
// gutter; back-edges (loops) arc down the left and are dashed.
function CfgGraph({ blocks }: { blocks: BasicBlock[] }) {
  const edges = useMemo(() => {
    const index = new Map<number, number>();
    blocks.forEach((b, i) => index.set(b.address, i));
    const es: { from: number; to: number; back: boolean }[] = [];
    blocks.forEach((b, i) => {
      for (const s of b.successors) {
        const j = index.get(s);
        if (j !== undefined) es.push({ from: i, to: j, back: j <= i });
      }
    });
    return es;
  }, [blocks]);

  const ROW = 118;
  const GUTTER = 48;
  const height = Math.max(blocks.length * ROW, 40);
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
            <path
              key={i}
              d={d}
              fill="none"
              stroke={color}
              strokeWidth="1.5"
              strokeDasharray={e.back ? "4 3" : undefined}
              markerEnd="url(#arrow)"
            />
          );
        })}
        <defs>
          <marker id="arrow" markerWidth="7" markerHeight="7" refX="5" refY="3" orient="auto">
            <path d="M0 0 L6 3 L0 6 Z" fill="#4a5568" />
          </marker>
        </defs>
      </svg>

      <div style={{ display: "flex", flexDirection: "column", flex: 1, minWidth: 0 }}>
        {blocks.map((b) => (
          <div key={b.address} style={{ height: ROW, paddingBottom: 8 }}>
            <Block block={b} />
          </div>
        ))}
      </div>
    </div>
  );
}
