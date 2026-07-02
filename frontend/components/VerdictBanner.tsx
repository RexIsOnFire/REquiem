import type { AnalysisReport } from "@/lib/types";
import { VERDICT_COLOR } from "@/lib/theme";

export function VerdictBanner({ report }: { report: AnalysisReport }) {
  const { identity: id } = report;
  const color = VERDICT_COLOR[report.verdict] ?? "#6b7280";
  return (
    <div
      className="card fade-in"
      style={{ display: "flex", gap: 20, alignItems: "center", marginTop: 18 }}
    >
      <div
        style={{
          fontWeight: 800,
          fontSize: 18,
          padding: "10px 18px",
          borderRadius: 10,
          background: color,
          color: "#0b0e14",
          whiteSpace: "nowrap",
        }}
      >
        {report.verdict.toUpperCase()}
      </div>
      <div style={{ minWidth: 0 }}>
        <div>
          <b>{report.classification ?? "unclassified"}</b>{" "}
          <span className="badge">
            {report.verdict_confidence.name} {report.verdict_confidence.value}%
          </span>
        </div>
        <div className="muted mono" style={{ overflow: "hidden", textOverflow: "ellipsis" }}>
          {id.filename} · {id.format.toUpperCase()} {id.arch || "?"}/{id.bitness || "?"}-bit ·{" "}
          {id.size.toLocaleString()} bytes
        </div>
      </div>
    </div>
  );
}
