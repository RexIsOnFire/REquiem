import type { AnalysisReport, AttackMatrix, IntelResult } from "./types";

// All requests go through the Next.js rewrite proxy at /api -> FastAPI.
const BASE = "/api";

export async function analyzeFile(
  file: File,
  intel = false,
): Promise<AnalysisReport> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${BASE}/analyze?intel=${intel}`, {
    method: "POST",
    body: form,
  });
  if (!res.ok) {
    throw new Error(`Analysis failed (${res.status}): ${await safeText(res)}`);
  }
  return res.json();
}

export async function lookupHash(
  hash: string,
  online = false,
): Promise<{ hash: string; note: string; results: IntelResult[] }> {
  const res = await fetch(`${BASE}/hash/${encodeURIComponent(hash)}?online=${online}`);
  if (!res.ok) throw new Error(`Lookup failed (${res.status})`);
  return res.json();
}

export async function getAttackMatrix(): Promise<AttackMatrix> {
  const res = await fetch(`${BASE}/attack/matrix`);
  if (!res.ok) throw new Error(`Matrix fetch failed (${res.status})`);
  return res.json();
}

export async function pdfBackendAvailable(): Promise<boolean> {
  try {
    const res = await fetch(`${BASE}/report/pdf-available`);
    if (!res.ok) return false;
    const j = await res.json();
    return Boolean(j.backend);
  } catch {
    return false;
  }
}

// Requests a server-rendered PDF. If the backend has no PDF engine it returns
// print-ready HTML instead (flagged via the X-ReQuiem-PDF header); we surface
// that so the caller can fall back to browser print-to-PDF.
export async function downloadPdf(
  file: File,
  intel = false,
): Promise<{ ok: true; blob: Blob; filename: string } | { ok: false; html: string }> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${BASE}/analyze/pdf?intel=${intel}`, {
    method: "POST",
    body: form,
  });
  if (!res.ok) throw new Error(`PDF request failed (${res.status})`);
  if (res.headers.get("X-ReQuiem-PDF") === "unavailable-html-fallback") {
    return { ok: false, html: await res.text() };
  }
  const stem = file.name.replace(/\.[^.]+$/, "");
  return { ok: true, blob: await res.blob(), filename: `${stem}.pdf` };
}

async function safeText(res: Response): Promise<string> {
  try {
    return await res.text();
  } catch {
    return "";
  }
}
