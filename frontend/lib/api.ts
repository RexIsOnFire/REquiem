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

async function safeText(res: Response): Promise<string> {
  try {
    return await res.text();
  } catch {
    return "";
  }
}
