"use client";
import { useState } from "react";
import { lookupHash } from "@/lib/api";
import type { IntelResult } from "@/lib/types";

const HASH_RE = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;

export function HashLookup() {
  const [hash, setHash] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<IntelResult[] | null>(null);
  const [note, setNote] = useState("");

  const valid = HASH_RE.test(hash.trim());

  async function run() {
    const h = hash.trim();
    if (!valid) {
      setError("Enter a valid MD5 (32), SHA1 (40), or SHA256 (64) hex hash.");
      return;
    }
    setBusy(true);
    setError(null);
    setResults(null);
    try {
      const res = await lookupHash(h, true); // online lookup
      setResults(res.results);
      setNote(res.note);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Lookup failed");
    } finally {
      setBusy(false);
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
        <button className="btn" disabled={busy || !valid} onClick={run}>
          {busy ? "Looking up…" : "Look up"}
        </button>
      </div>
      <div className="muted small" style={{ marginTop: 8 }}>
        Metadata only — queries MalwareBazaar (and VirusTotal if configured).
        ReQuiem never downloads sample binaries.
      </div>

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
