"use client";
import { useState } from "react";
import type { AnalysisReport } from "@/lib/types";

// One PDF path for everything: POST the already-computed report to /report/pdf,
// which renders the PRINT-OPTIMIZED HTML server-side (Playwright) — a proper
// light-themed, paginated document. Works identically for uploaded samples and
// hash investigations (no source file needed). If the server has no PDF engine
// it returns print-ready HTML, which we open and let the browser save as PDF —
// still the clean report, never the live dark app DOM.
export function PdfButton({ report }: { report: AnalysisReport }) {
  const [busy, setBusy] = useState(false);

  async function download() {
    setBusy(true);
    try {
      const res = await fetch("/api/report/pdf", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(report),
      });
      if (res.headers.get("X-ReQuiem-PDF") === "unavailable-html-fallback") {
        openAndPrint(await res.text());
        return;
      }
      const blob = await res.blob();
      const stem =
        (report.identity.filename || "report").replace(/\.[^.]+$/, "").replace(/[…\s]/g, "") ||
        "report";
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${stem}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setBusy(false);
    }
  }

  return (
    <button className="btn btn-ghost small" disabled={busy} onClick={download}>
      {busy ? "Preparing…" : "⬇ Download PDF"}
    </button>
  );
}

function openAndPrint(htmlDoc: string) {
  const w = window.open("", "_blank");
  if (!w) return;
  w.document.open();
  w.document.write(htmlDoc);
  w.document.close();
  w.onload = () => setTimeout(() => w.print(), 350);
}
