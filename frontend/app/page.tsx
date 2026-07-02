"use client";
import { useState } from "react";
import type { AnalysisReport } from "@/lib/types";
import { Uploader } from "@/components/Uploader";
import { ReportView } from "@/components/ReportView";

export default function Home() {
  const [report, setReport] = useState<AnalysisReport | null>(null);

  if (report) {
    return <ReportView report={report} onReset={() => setReport(null)} />;
  }

  return (
    <div style={{ maxWidth: 680, margin: "0 auto", paddingTop: 56 }}>
      <h1 style={{ fontSize: 30, margin: "0 0 8px", textAlign: "center" }}>
        ReQuiem
      </h1>
      <p className="muted" style={{ textAlign: "center", margin: "0 0 4px" }}>
        Malware analysis workbench
      </p>
      <p
        className="muted small"
        style={{ textAlign: "center", margin: "0 0 32px" }}
      >
        One upload · one investigation · one report · one ATT&amp;CK view · one IOC export
      </p>

      <Uploader onReport={setReport} />

      <div className="grid" style={{ marginTop: 28 }}>
        <Feature
          title="Explainable"
          body="Every verdict cites the evidence that produced it — click any finding to see the proof."
        />
        <Feature
          title="Language ID"
          body="Fingerprints Go, Rust, .NET, C/C++, Delphi, Nim and more, with the compiler and confidence."
        />
        <Feature
          title="ATT&CK mapped"
          body="Behavior is inferred into MITRE techniques and rendered as an interactive heatmap."
        />
        <Feature
          title="Safe"
          body="Static-first. Metadata-only hash lookups. Samples are never executed or redistributed."
        />
      </div>
    </div>
  );
}

function Feature({ title, body }: { title: string; body: string }) {
  return (
    <div className="card">
      <h3>{title}</h3>
      <div className="small">{body}</div>
    </div>
  );
}
