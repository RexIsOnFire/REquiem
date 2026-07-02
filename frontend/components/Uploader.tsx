"use client";
import { useCallback, useRef, useState } from "react";
import type { AnalysisReport } from "@/lib/types";
import { analyzeFile } from "@/lib/api";

export function Uploader({
  onReport,
}: {
  onReport: (r: AnalysisReport) => void;
}) {
  const [drag, setDrag] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [intel, setIntel] = useState(false);
  const [filename, setFilename] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const run = useCallback(
    async (file: File) => {
      setBusy(true);
      setError(null);
      setFilename(file.name);
      try {
        const report = await analyzeFile(file, intel);
        onReport(report);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Analysis failed");
      } finally {
        setBusy(false);
      }
    },
    [intel, onReport],
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDrag(false);
      const file = e.dataTransfer.files?.[0];
      if (file) run(file);
    },
    [run],
  );

  return (
    <div>
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDrag(true);
        }}
        onDragLeave={() => setDrag(false)}
        onDrop={onDrop}
        onClick={() => !busy && inputRef.current?.click()}
        className="card"
        style={{
          textAlign: "center",
          padding: "48px 24px",
          borderStyle: "dashed",
          borderColor: drag ? "var(--accent)" : "var(--line)",
          background: drag ? "var(--panel2)" : "var(--panel)",
          cursor: busy ? "default" : "pointer",
          transition: "all 0.15s",
        }}
      >
        <input
          ref={inputRef}
          type="file"
          hidden
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) run(f);
          }}
        />
        {busy ? (
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 14 }}>
            <div className="spinner" />
            <div className="muted">Analyzing {filename}…</div>
          </div>
        ) : (
          <>
            <div style={{ fontSize: 34, marginBottom: 8 }}>🗎</div>
            <div style={{ fontSize: 16, fontWeight: 600 }}>
              Drop a sample here, or click to browse
            </div>
            <div className="muted small" style={{ marginTop: 6 }}>
              PE · ELF · Mach-O · Office · scripts — analyzed statically, never executed
            </div>
          </>
        )}
      </div>

      <label
        className="small"
        style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 14, cursor: "pointer" }}
      >
        <input type="checkbox" checked={intel} onChange={(e) => setIntel(e.target.checked)} />
        Enrich with online hash-reputation lookup (MalwareBazaar / VirusTotal)
      </label>

      {error && (
        <div
          className="card"
          style={{ marginTop: 14, borderColor: "#ef4444", color: "#fca5a5" }}
        >
          {error}
          <div className="muted small" style={{ marginTop: 4 }}>
            Is the API running? Start it with:{" "}
            <span className="mono">uvicorn requiem.api.app:app --port 8000</span>
          </div>
        </div>
      )}
    </div>
  );
}
