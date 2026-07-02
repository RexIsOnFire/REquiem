"use client";
import { useMemo, useState } from "react";
import type { AttackTechnique } from "@/lib/types";
import { confidenceShade } from "@/lib/theme";

// Canonical tactic order — mirrors requiem/attack/techniques.py TACTIC_ORDER.
const TACTIC_ORDER = [
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

export function AttackHeatmap({ attack }: { attack: AttackTechnique[] }) {
  const [hover, setHover] = useState<AttackTechnique | null>(null);

  const byTactic = useMemo(() => {
    const map: Record<string, AttackTechnique[]> = {};
    for (const at of attack) (map[at.tactic] ??= []).push(at);
    return map;
  }, [attack]);

  if (attack.length === 0) {
    return <p className="muted">No ATT&CK techniques inferred.</p>;
  }

  const cols = [
    ...TACTIC_ORDER.filter((t) => byTactic[t]),
    ...Object.keys(byTactic).filter((t) => !TACTIC_ORDER.includes(t)),
  ];
  const maxRows = Math.max(...cols.map((c) => byTactic[c].length));

  return (
    <div>
      <div className="scroll">
        <table style={{ borderCollapse: "separate", borderSpacing: 4 }}>
          <thead>
            <tr>
              {cols.map((c) => (
                <th
                  key={c}
                  style={{
                    minWidth: 128,
                    fontSize: 10.5,
                    textAlign: "center",
                    padding: "4px 6px",
                    color: "var(--mut)",
                    borderBottom: "none",
                  }}
                >
                  {c}
                  <div style={{ color: "#5b6472", fontWeight: 400 }}>
                    {byTactic[c].length}
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {Array.from({ length: maxRows }).map((_, r) => (
              <tr key={r}>
                {cols.map((c) => {
                  const at = byTactic[c][r];
                  if (!at)
                    return (
                      <td
                        key={c}
                        style={{
                          background: "var(--panel)",
                          borderRadius: 6,
                          border: "1px solid var(--line)",
                        }}
                      />
                    );
                  const active = hover?.technique_id === at.technique_id;
                  return (
                    <td
                      key={c}
                      onMouseEnter={() => setHover(at)}
                      onMouseLeave={() => setHover(null)}
                      style={{
                        background: confidenceShade(at.confidence.name),
                        borderRadius: 6,
                        // Ring + brightness signals hover WITHOUT scaling, so the
                        // cell never overflows/clips against the scroll edges.
                        boxShadow: active ? "0 0 0 2px #fff inset" : "none",
                        filter: active ? "brightness(1.25)" : "none",
                        padding: "8px 8px",
                        color: "#fff",
                        cursor: "pointer",
                        minWidth: 128,
                        transition: "filter 0.1s, box-shadow 0.1s",
                      }}
                    >
                      <b style={{ fontSize: 11 }}>{at.technique_id}</b>
                      <div style={{ fontSize: 10.5, color: "#f3d3c9", lineHeight: 1.25 }}>
                        {at.name}
                      </div>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="card" style={{ marginTop: 12, minHeight: 54 }}>
        {hover ? (
          <div className="fade-in">
            <b>
              {hover.technique_id} · {hover.name}
            </b>{" "}
            <span className="badge">{hover.tactic}</span>{" "}
            <span className="badge">
              {hover.confidence.name} {hover.confidence.value}%
            </span>
            {hover.evidence.length > 0 && (
              <div className="muted small" style={{ marginTop: 6 }}>
                Evidence: {hover.evidence.map((e) => e.detail).join("; ")}
              </div>
            )}
          </div>
        ) : (
          <span className="muted small">
            Hover a technique to see the tactic and the evidence that inferred it.
          </span>
        )}
      </div>
    </div>
  );
}
