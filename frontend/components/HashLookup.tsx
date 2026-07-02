"use client";
import { useState } from "react";
import { investigateHash, lookupHash } from "@/lib/api";
import type { AnalysisReport, IntelResult } from "@/lib/types";

const HASH_RE = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;

export function HashLookup({
  onReport,
}: {
  onReport: (r: AnalysisReport) => void;
}) {
  const [hash, setHash] = useState("");
  const [busy, setBusy] = useState<null | "lookup" | "investigate">(null);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<IntelResult[] | null>(null);
  const [note, setNote] = useState("");
  const [cloudNote, setCloudNote] = useState("");

  const valid = HASH_RE.test(hash.trim());

  async function run() {
    const h = hash.trim();
    if (!valid) {
      setError("Enter a valid MD5 (32), SHA1 (40), or SHA256 (64) hex hash.");
      return;
    }
    setBusy("lookup");
    setError(null);
    setResults(null);
    setCloudNote("");
    try {
      const res = await lookupHash(h, true); // online lookup
      setResults(res.results);
      setNote(res.note);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Lookup failed");
    } finally {
      setBusy(null);
    }
  }

  // Full cloud investigation: pull any existing detonation (Triage/VT/HA) and
  // render the complete report — behavior, ATT&CK, findings — from the hash.
  async function investigate() {
    const h = hash.trim();
    if (!valid) return;
    setBusy("investigate");
    setError(null);
    try {
      const res = await investigateHash(h);
      const found = res.sources.filter((s) => s.found).map((s) => s.source);
      if (found.length === 0) {
        setCloudNote(
          "No existing cloud detonation found for this hash (Triage / VirusTotal / Hybrid Analysis). Upload the sample to analyze it statically.",
        );
        return;
      }
      onReport(res.report);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Investigation failed");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div>
      <div style={{ display: "flex", gap: 8 }}>
        <input
          value={hash}
          onChange={(e) => setHash(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && run()}
          placeholder="Paste a SHA256 / SHA1 / MD5 hash…"
          className="mono"
          style={{
            flex: 1,
            background: "var(--panel)",
            border: `1px solid ${hash && !valid ? "#ef4444" : "var(--line)"}`,
            borderRadius: 8,
            color: "var(--tx)",
            padding: "11px 12px",
            fontSize: 13,
          }}
        />
        <button className="btn btn-ghost" disabled={!!busy || !valid} onClick={run}>
          {busy === "lookup" ? "Looking up…" : "Reputation"}
        </button>
        <button className="btn" disabled={!!busy || !valid} onClick={investigate}>
          {busy === "investigate" ? "Investigating…" : "Investigate"}
        </button>
      </div>
      <div className="muted small" style={{ marginTop: 8 }}>
        <b>Reputation</b>: family/tags from MalwareBazaar &amp; VirusTotal.{" "}
        <b>Investigate</b>: full behavioral report (process tree, network,
        ATT&amp;CK) from an existing cloud detonation — no upload, no local sandbox.
        ReQuiem never downloads sample binaries.
      </div>

      {cloudNote && (
        <div className="card" style={{ marginTop: 14 }}>
          <span className="small muted">{cloudNote}</span>
        </div>
      )}

      {error && (
        <div className="card" style={{ marginTop: 14, borderColor: "#ef4444", color: "#fca5a5" }}>
          {error}
        </div>
      )}

      {results && (
        <div className="fade-in" style={{ marginTop: 16 }}>
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Status</th>
                  <th>Family</th>
                  <th>First seen</th>
                  <th>Tags</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {results.map((r, i) => (
                  <tr key={i}>
                    <td>{r.source}</td>
                    <td>
                      <span
                        className="badge"
                        style={{
                          borderColor: r.known ? "#ef4444" : "var(--line)",
                          color: r.known ? "#fca5a5" : "var(--mut)",
                        }}
                      >
                        {r.known ? "KNOWN" : "unknown"}
                      </span>
                    </td>
                    <td>{r.family ?? "—"}</td>
                    <td className="mono small muted">{r.first_seen ?? "—"}</td>
                    <td className="small">
                      {r.tags.length ? r.tags.slice(0, 6).join(", ") : "—"}
                    </td>
                    <td className="muted small">{r.detail ?? ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {note && (
            <div className="muted small" style={{ marginTop: 8 }}>
              {note}
            </div>
          )}
          {results.every((r) => !r.known) && (
            <div className="muted small" style={{ marginTop: 8 }}>
              Not found in the configured sources. To analyze the actual file,
              upload it on the <b>Upload sample</b> tab.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
