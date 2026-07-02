"use client";
import { useEffect, useState } from "react";
import type { AnalysisReport } from "@/lib/types";
import { Uploader } from "@/components/Uploader";
import { HashLookup } from "@/components/HashLookup";
import { ReportView } from "@/components/ReportView";
import { useInvestigation } from "@/lib/investigation";

type Tab = "upload" | "hash";

export default function Home() {
  const [report, setReport] = useState<AnalysisReport | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [intel, setIntel] = useState(false);
  const [tab, setTab] = useState<Tab>("upload");
  const { register } = useInvestigation();

  function handleReport(r: AnalysisReport, f: File, usedIntel: boolean) {
    setReport(r);
    setFile(f);
    setIntel(usedIntel);
  }

  function reset() {
    setReport(null);
    setFile(null);
    setTab("upload");
  }

  // Let the nav's "New investigation" trigger our reset.
  useEffect(() => register(reset), [register]);

  if (report) {
    return (
      <ReportView report={report} sourceFile={file} intel={intel} onReset={reset} />
    );
  }

  return (
    <div style={{ maxWidth: 720, margin: "0 auto", paddingTop: 48 }}>
      <h1 style={{ fontSize: 30, margin: "0 0 8px", textAlign: "center" }}>ReQuiem</h1>
      <p className="muted" style={{ textAlign: "center", margin: "0 0 4px" }}>
        Malware analysis workbench
      </p>
      <p className="muted small" style={{ textAlign: "center", margin: "0 0 28px" }}>
        One upload · one investigation · one report · one ATT&amp;CK view · one IOC export
      </p>

      <div
        style={{
          display: "flex",
          gap: 6,
          justifyContent: "center",
          marginBottom: 18,
        }}
      >
        <TabButton active={tab === "upload"} onClick={() => setTab("upload")}>
          Upload sample
        </TabButton>
        <TabButton active={tab === "hash"} onClick={() => setTab("hash")}>
          Hash lookup
        </TabButton>
      </div>

      {tab === "upload" ? <Uploader onReport={handleReport} /> : <HashLookup />}

      <div className="grid" style={{ marginTop: 28 }}>
        <Feature title="Explainable" body="Every verdict cites the evidence that produced it — click any finding to see the proof." />
        <Feature title="Language ID" body="Fingerprints Go, Rust, .NET, C/C++, Delphi, Nim and more, with the compiler and confidence." />
        <Feature title="ATT&CK mapped" body="Behavior is inferred into MITRE techniques and rendered as an interactive heatmap." />
        <Feature title="Safe" body="Static-first. Metadata-only hash lookups. Samples are never executed or redistributed." />
      </div>
    </div>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={active ? "btn" : "btn btn-ghost"}
      style={{ padding: "8px 18px", fontSize: 13 }}
    >
      {children}
    </button>
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
