"use client";
import { useEffect, useState } from "react";
import { downloadPdf, pdfBackendAvailable } from "@/lib/api";

// Two ways to get a PDF:
//   1. Server-rendered (WeasyPrint/Playwright) — a real .pdf download.
//   2. Browser print-to-PDF of the print-ready HTML report — always available.
// We probe the backend once and offer the best path, but the print fallback is
// always present so the feature never dead-ends.
export function PdfButton({
  sourceFile,
  intel,
}: {
  sourceFile: File | null;
  intel: boolean;
}) {
  const [serverPdf, setServerPdf] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    pdfBackendAvailable().then(setServerPdf);
  }, []);

  async function handleServerPdf() {
    if (!sourceFile) return;
    setBusy(true);
    try {
      const res = await downloadPdf(sourceFile, intel);
      if (res.ok) {
        const url = URL.createObjectURL(res.blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = res.filename;
        a.click();
        URL.revokeObjectURL(url);
      } else {
        // Backend lost its PDF engine mid-session — open the HTML and print.
        openAndPrint(res.html);
      }
    } finally {
      setBusy(false);
    }
  }

  // Fallback path: re-render the report HTML in a new window and invoke print.
  async function handlePrintPdf() {
    if (!sourceFile) {
      window.print();
      return;
    }
    setBusy(true);
    try {
      const form = new FormData();
      form.append("file", sourceFile);
      const res = await fetch(`/api/analyze/html?intel=${intel}`, {
        method: "POST",
        body: form,
      });
      openAndPrint(await res.text());
    } finally {
      setBusy(false);
    }
  }

  const canServer = serverPdf && sourceFile;

  return (
    <button
      className="btn btn-ghost small"
      disabled={busy}
      onClick={canServer ? handleServerPdf : handlePrintPdf}
      title={
        canServer
          ? "Download a server-rendered PDF"
          : "Open the print-ready report and save as PDF"
      }
    >
      {busy ? "Preparing…" : canServer ? "⬇ Download PDF" : "🖨 Save as PDF"}
    </button>
  );
}

function openAndPrint(html: string) {
  const w = window.open("", "_blank");
  if (!w) return;
  w.document.open();
  w.document.write(html);
  w.document.close();
  // Give the browser a tick to lay out before invoking print.
  w.onload = () => setTimeout(() => w.print(), 350);
}
