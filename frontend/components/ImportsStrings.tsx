"use client";
import { useMemo, useState } from "react";
import type { AnalysisReport } from "@/lib/types";

// Group imports by their DLL prefix ("kernel32.dll!CreateFileW") and flag the
// behaviorally-interesting APIs so an analyst sees capability at a glance.
const SUSPICIOUS_API =
  /virtualalloc|writeprocessmemory|createremotethread|loadlibrary|getprocaddress|winexec|shellexecute|createprocess|regsetvalue|reg(create|open)key|cryptencrypt|bcryptencrypt|internetopen|urldownload|wsastartup|socket|connect|isdebuggerpresent|ntmapviewofsection|queueuserapc|setwindowshook|adjusttokenprivileges|openprocess/i;

function copy(text: string) {
  navigator.clipboard?.writeText(text).catch(() => {});
}

function groupImports(imports: string[]) {
  const groups: Record<string, { fn: string; suspicious: boolean }[]> = {};
  for (const imp of imports) {
    const [dll, fn] = imp.includes("!") ? imp.split("!", 2) : ["(unknown)", imp];
    (groups[dll] ??= []).push({ fn, suspicious: SUSPICIOUS_API.test(fn) });
  }
  return groups;
}

export function ImportsStrings({ report }: { report: AnalysisReport }) {
  const [showAll, setShowAll] = useState(false);
  const groups = useMemo(() => groupImports(report.imports), [report.imports]);
  const dlls = Object.keys(groups).sort();
  const suspCount = report.imports.filter((i) =>
    SUSPICIOUS_API.test(i.split("!").pop() || ""),
  ).length;

  const hasImports = report.imports.length > 0;
  const hasStrings = report.strings_of_interest.length > 0;
  const hasExports = report.exports.length > 0;
  if (!hasImports && !hasStrings && !hasExports) {
    return <p className="muted small">No imports or notable strings extracted.</p>;
  }

  return (
    <div>
      {hasImports && (
        <div className="card" style={{ marginBottom: 12 }}>
          <h3 style={{ display: "flex", alignItems: "center", gap: 8 }}>
            Imports
            <span className="badge">{report.imports.length}</span>
            {suspCount > 0 && (
              <span
                className="badge"
                style={{ borderColor: "#f97316", color: "#fdba74" }}
                title="Behaviorally-interesting APIs"
              >
                {suspCount} notable
              </span>
            )}
            <button
              className="btn btn-ghost small"
              style={{ marginLeft: "auto", padding: "3px 8px" }}
              onClick={() => copy(report.imports.join("\n"))}
            >
              copy
            </button>
          </h3>
          <div
            className="grid"
            style={{ gridTemplateColumns: "repeat(auto-fit,minmax(260px,1fr))", gap: 10 }}
          >
            {dlls.map((dll) => {
              const fns = groups[dll];
              const shown = showAll ? fns : fns.slice(0, 12);
              return (
                <div key={dll} style={{ minWidth: 0 }}>
                  <div className="mono small" style={{ color: "#7c9cff", marginBottom: 3 }}>
                    {dll} <span className="muted">({fns.length})</span>
                  </div>
                  <ul
                    className="mono"
                    style={{ margin: 0, paddingLeft: 16, fontSize: 12, lineHeight: 1.5 }}
                  >
                    {shown.map((f, i) => (
                      <li
                        key={i}
                        style={{
                          color: f.suspicious ? "#fdba74" : "var(--tx)",
                          wordBreak: "break-all",
                        }}
                      >
                        {f.fn}
                        {f.suspicious && <span title="notable API"> ●</span>}
                      </li>
                    ))}
                    {!showAll && fns.length > 12 && (
                      <li className="muted">+{fns.length - 12} more</li>
                    )}
                  </ul>
                </div>
              );
            })}
          </div>
          {report.imports.length > 24 && (
            <button
              className="btn btn-ghost small"
              style={{ marginTop: 8 }}
              onClick={() => setShowAll((s) => !s)}
            >
              {showAll ? "Show less" : "Show all imports"}
            </button>
          )}
        </div>
      )}

      <div
        className="grid"
        style={{ gridTemplateColumns: "repeat(auto-fit,minmax(300px,1fr))" }}
      >
        {hasExports && (
          <div className="card">
            <h3 style={{ display: "flex", alignItems: "center", gap: 8 }}>
              Exports <span className="badge">{report.exports.length}</span>
              <button
                className="btn btn-ghost small"
                style={{ marginLeft: "auto", padding: "3px 8px" }}
                onClick={() => copy(report.exports.join("\n"))}
              >
                copy
              </button>
            </h3>
            <ul
              className="mono"
              style={{ margin: 0, paddingLeft: 16, fontSize: 12, maxHeight: 220, overflow: "auto" }}
            >
              {report.exports.slice(0, 200).map((e, i) => (
                <li key={i} style={{ wordBreak: "break-all" }}>
                  {e}
                </li>
              ))}
            </ul>
          </div>
        )}

        {hasStrings && (
          <div className="card">
            <h3 style={{ display: "flex", alignItems: "center", gap: 8 }}>
              Notable strings <span className="badge">{report.strings_of_interest.length}</span>
              <button
                className="btn btn-ghost small"
                style={{ marginLeft: "auto", padding: "3px 8px" }}
                onClick={() => copy(report.strings_of_interest.join("\n"))}
              >
                copy
              </button>
            </h3>
            <ul
              className="mono"
              style={{ margin: 0, paddingLeft: 16, fontSize: 12, maxHeight: 260, overflow: "auto" }}
            >
              {report.strings_of_interest.slice(0, 300).map((s, i) => (
                <li key={i} style={{ wordBreak: "break-all" }}>
                  {s}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}
