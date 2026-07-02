"use client";
import type { AnalysisReport, IOCSet } from "@/lib/types";

function copy(text: string) {
  navigator.clipboard?.writeText(text).catch(() => {});
}

function IOCGroup({ name, values }: { name: string; values: string[] }) {
  if (values.length === 0) return null;
  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <h3 style={{ display: "flex", alignItems: "center", gap: 8 }}>
        {name}
        <span className="badge">{values.length}</span>
        <button
          className="btn btn-ghost small"
          style={{ marginLeft: "auto", padding: "3px 8px" }}
          onClick={() => copy(values.join("\n"))}
        >
          copy
        </button>
      </h3>
      <ul
        className="mono small"
        style={{ margin: 0, paddingLeft: 16, maxHeight: 190, overflow: "auto", wordBreak: "break-all" }}
      >
        {values.slice(0, 100).map((v, i) => (
          <li key={i}>{v}</li>
        ))}
      </ul>
    </div>
  );
}

const GROUPS: { key: keyof IOCSet; label: string }[] = [
  { key: "urls", label: "URLs" },
  { key: "domains", label: "Domains" },
  { key: "ipv4", label: "IPv4" },
  { key: "registry_keys", label: "Registry keys" },
  { key: "mutexes", label: "Mutexes" },
  { key: "bitcoin", label: "Bitcoin" },
  { key: "emails", label: "Emails" },
  { key: "file_paths", label: "File paths" },
];

function exportAll(report: AnalysisReport): string {
  const i = report.iocs;
  const lines: string[] = [`# ReQuiem IOC export — ${report.identity.filename}`, `# sha256 ${report.identity.sha256}`, ""];
  for (const { key, label } of GROUPS) {
    const vals = i[key] as string[];
    if (vals.length) {
      lines.push(`## ${label}`);
      lines.push(...vals);
      lines.push("");
    }
  }
  return lines.join("\n");
}

export function IOCPanel({ report }: { report: AnalysisReport }) {
  const i = report.iocs;
  const empty = GROUPS.every(({ key }) => (i[key] as string[]).length === 0);

  function download() {
    const blob = new Blob([exportAll(report)], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${report.identity.filename}.iocs.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }

  if (empty) return <p className="muted">No IOCs extracted.</p>;

  return (
    <div>
      <div style={{ marginBottom: 12 }}>
        <button className="btn btn-ghost small" onClick={download}>
          ⬇ Export all IOCs
        </button>
      </div>
      <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit,minmax(280px,1fr))" }}>
        {GROUPS.map(({ key, label }) => (
          <IOCGroup key={key} name={label} values={i[key] as string[]} />
        ))}
      </div>
    </div>
  );
}
