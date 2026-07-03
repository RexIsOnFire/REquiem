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
    credentials: "same-origin",
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
  const res = await fetch(`${BASE}/hash/${encodeURIComponent(hash)}?online=${online}`, {
    credentials: "same-origin",
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Lookup failed (${res.status})`);
  }
  return res.json();
}

// --- auth + per-user keys ------------------------------------------------
export interface AuthUser {
  id: number;
  email: string;
  created_at?: string;
}

async function authPost(path: string, body: object): Promise<AuthUser> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    credentials: "same-origin",
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `Request failed (${res.status})`);
  return data;
}

export const register = (email: string, password: string) =>
  authPost("/auth/register", { email, password });
export const login = (email: string, password: string) =>
  authPost("/auth/login", { email, password });

export async function logout(): Promise<void> {
  await fetch(`${BASE}/auth/logout`, { method: "POST", credentials: "same-origin" });
}

export async function me(): Promise<AuthUser | null> {
  const res = await fetch(`${BASE}/auth/me`, { credentials: "same-origin" });
  if (res.status === 401) return null;
  if (!res.ok) return null;
  return res.json();
}

export async function getKeyStatus(): Promise<{
  allowed: string[];
  status: Record<string, boolean>;
}> {
  const res = await fetch(`${BASE}/keys`, { credentials: "same-origin" });
  if (!res.ok) throw new Error("not authenticated");
  return res.json();
}

export async function saveKey(name: string, value: string): Promise<void> {
  const res = await fetch(`${BASE}/keys`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, value }),
    credentials: "same-origin",
  });
  if (!res.ok) throw new Error(`Failed to save ${name}`);
}

export async function deleteKey(name: string): Promise<void> {
  await fetch(`${BASE}/keys/${encodeURIComponent(name)}`, {
    method: "DELETE",
    credentials: "same-origin",
  });
}

export async function getAttackMatrix(): Promise<AttackMatrix> {
  const res = await fetch(`${BASE}/attack/matrix`);
  if (!res.ok) throw new Error(`Matrix fetch failed (${res.status})`);
  return res.json();
}

// Full by-hash cloud investigation: intel + existing cloud detonation
// (Triage/VT/Hybrid Analysis) -> a report with behavior + ATT&CK. No upload.
export async function investigateHash(hash: string): Promise<{
  hash: string;
  note: string;
  sources: { source: string; found: boolean; note: string }[];
  report: AnalysisReport;
}> {
  const res = await fetch(`${BASE}/investigate/${encodeURIComponent(hash)}`, {
    credentials: "same-origin",
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Investigation failed (${res.status})`);
  }
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
