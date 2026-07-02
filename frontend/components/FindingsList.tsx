"use client";
import { useState } from "react";
import type { Finding } from "@/lib/types";
import { SEVERITY_COLOR } from "@/lib/theme";

function sortKey(f: Finding): number {
  return f.severity.value * 1000 + f.confidence.value;
}

function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const color = SEVERITY_COLOR[finding.severity.name] ?? "#5b6472";
  const hasDetail = finding.evidence.length > 0 || finding.attack_techniques.length > 0;
  return (
    <div
      className="card"
      style={{ borderLeft: `4px solid ${color}`, margin: "10px 0", cursor: hasDetail ? "pointer" : "default" }}
      onClick={() => hasDetail && setOpen((o) => !o)}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <span
          style={{
            background: color,
            color: "#0b0e14",
            fontWeight: 700,
            fontSize: 10,
            padding: "2px 7px",
            borderRadius: 5,
          }}
        >
          {finding.severity.name}
        </span>
        <b>{finding.title}</b>
        <span className="badge">
          {finding.confidence.name} {finding.confidence.value}%
        </span>
        {finding.tags.includes("simulated") && (
          <span
            className="badge"
            style={{ background: "#7c4a03", color: "#ffd7a1", borderColor: "#7c4a03" }}
          >
            simulated
          </span>
        )}
        {hasDetail && (
          <span className="muted small" style={{ marginLeft: "auto" }}>
            {open ? "▲" : "▼"}
          </span>
        )}
      </div>
      <p style={{ margin: "8px 0 0" }}>{finding.description}</p>

      {open && (
        <div className="fade-in">
          {finding.evidence.length > 0 && (
            <ul className="muted" style={{ margin: "10px 0 0", paddingLeft: 18 }}>
              {finding.evidence.map((e, i) => (
                <li key={i} style={{ margin: "3px 0" }}>
                  {e.detail}
                  {e.locator && (
                    <span className="mono" style={{ color: "#6b7f9e", marginLeft: 6 }}>
                      [{e.locator}]
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )}
          {finding.attack_techniques.length > 0 && (
            <div style={{ marginTop: 10 }}>
              {finding.attack_techniques.map((t) => (
                <span key={t} className="pill">
                  {t}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function FindingsList({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return <p className="muted">No behavioral findings.</p>;
  }
  const ordered = [...findings].sort((a, b) => sortKey(b) - sortKey(a));
  return (
    <div>
      {ordered.map((f, i) => (
        <FindingCard key={`${f.title}-${i}`} finding={f} />
      ))}
    </div>
  );
}
