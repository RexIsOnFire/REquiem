"use client";
import { useState } from "react";
import type { MemoryRegion } from "@/lib/types";
import { hexAddr, humanBytes, kindColor, KIND_COLOR } from "@/lib/memory";

// Protection triplet as three fixed-position cells so R/W/X line up like a
// permission matrix; the X cell is emphasized because executable+writable or
// executable+unbacked is the interesting case.
function Prot({ protection }: { protection: string }) {
  const bits = [
    ["r", protection.includes("r")],
    ["w", protection.includes("w")],
    ["x", protection.includes("x")],
  ] as const;
  return (
    <span style={{ display: "inline-flex", gap: 2 }}>
      {bits.map(([ch, on]) => (
        <span
          key={ch}
          className="mono"
          style={{
            width: 15,
            textAlign: "center",
            borderRadius: 3,
            fontWeight: 700,
            background: on ? (ch === "x" ? "#7f1d1d" : "var(--panel2)") : "transparent",
            color: on ? (ch === "x" ? "#fecaca" : "var(--tx)") : "var(--line)",
          }}
        >
          {on ? ch.toUpperCase() : "–"}
        </span>
      ))}
    </span>
  );
}

function Legend() {
  const kinds = ["image", "mapped", "stack", "private", "shellcode"];
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 12, marginBottom: 10 }}>
      {kinds.map((k) => (
        <span key={k} className="small muted" style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
          <span style={{ width: 10, height: 10, borderRadius: 2, background: KIND_COLOR[k] }} />
          {k}
        </span>
      ))}
    </div>
  );
}

export function MemoryMap({ regions }: { regions: MemoryRegion[] }) {
  const [hover, setHover] = useState<MemoryRegion | null>(null);
  if (regions.length === 0) {
    return <p className="muted">No memory regions captured.</p>;
  }
  // Size bars use a log scale — regions span KB to GB, so linear would make
  // everything but the largest invisible.
  const maxLog = Math.max(...regions.map((r) => Math.log2(r.size)));
  const minLog = Math.min(...regions.map((r) => Math.log2(r.size)));
  const span = Math.max(1, maxLog - minLog);

  return (
    <div>
      <Legend />
      <div className="scroll">
        <table>
          <thead>
            <tr>
              <th>Base address</th>
              <th>Size</th>
              <th>Prot</th>
              <th>Backing</th>
              <th style={{ width: "34%" }}>Region</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {regions.map((r, i) => {
              const frac = (Math.log2(r.size) - minLog) / span;
              const color = kindColor(r);
              return (
                <tr
                  key={i}
                  onMouseEnter={() => setHover(r)}
                  onMouseLeave={() => setHover(null)}
                  style={{ background: hover === r ? "var(--panel2)" : undefined }}
                >
                  <td className="mono">{hexAddr(r.base)}</td>
                  <td className="mono">{humanBytes(r.size)}</td>
                  <td>
                    <Prot protection={r.protection} />
                  </td>
                  <td className="small">
                    {r.backed ? (
                      <span className="muted">file-backed</span>
                    ) : (
                      <span style={{ color: r.suspicious ? "#fca5a5" : "var(--mut)" }}>
                        unbacked
                      </span>
                    )}
                  </td>
                  <td>
                    <span
                      style={{ display: "inline-flex", alignItems: "center", gap: 6 }}
                    >
                      <span style={{ width: 9, height: 9, borderRadius: 2, background: color, flex: "none" }} />
                      <span className="small">{r.label}</span>
                      {r.suspicious && (
                        <span
                          className="small"
                          style={{ color: "#fca5a5", fontWeight: 700 }}
                          title="Suspicious region"
                        >
                          ⚠
                        </span>
                      )}
                    </span>
                  </td>
                  <td style={{ width: 130 }}>
                    <span className="bar" style={{ width: 120 }}>
                      <span
                        className="fill"
                        style={{ width: `${Math.max(6, frac * 100)}%`, background: color }}
                      />
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="card" style={{ marginTop: 10, minHeight: 40 }}>
        {hover ? (
          <span className="small fade-in">
            <b className="mono">{hexAddr(hover.base)}</b> · {humanBytes(hover.size)} ·{" "}
            <span className="mono">{hover.protection}</span> · {hover.kind} ·{" "}
            {hover.backed ? "file-backed" : "unbacked (private)"}
            {hover.suspicious && (
              <span style={{ color: "#fca5a5" }}>
                {" "}
                — flagged: {hover.protection.includes("x") && !hover.backed
                  ? "executable memory with no file backing (injected/unpacked code)"
                  : "unusually large private commit"}
              </span>
            )}
          </span>
        ) : (
          <span className="muted small">
            Hover a region. Unbacked executable memory and outsized private commits are
            the tells for injection and bulk encryption.
          </span>
        )}
      </div>
    </div>
  );
}
