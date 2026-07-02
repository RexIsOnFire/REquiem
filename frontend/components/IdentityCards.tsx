import type { AnalysisReport } from "@/lib/types";

function avgEntropy(report: AnalysisReport): number {
  const total = report.sections.reduce((a, s) => a + s.raw_size, 0) || 1;
  const weighted = report.sections.reduce((a, s) => a + s.entropy * s.raw_size, 0);
  return weighted / total;
}

export function IdentityCards({ report }: { report: AnalysisReport }) {
  const lang = report.languages[0];
  const packer = report.packers[0];
  const id = report.identity;
  return (
    <div className="grid">
      <div className="card">
        <h3>Language</h3>
        {lang && lang.language !== "unknown" ? (
          <>
            <div className="big">{lang.language}</div>
            <div className="muted">
              {lang.compiler || ""}{" "}
              <span className="badge">
                {lang.confidence.name} {lang.confidence.value}%
              </span>
            </div>
            {lang.evidence.length > 0 && (
              <ul className="muted small" style={{ margin: "8px 0 0", paddingLeft: 16 }}>
                {lang.evidence.slice(0, 4).map((e, i) => (
                  <li key={i}>{e.detail}</li>
                ))}
              </ul>
            )}
          </>
        ) : (
          <div className="big muted">—</div>
        )}
      </div>

      <div className="card">
        <h3>Packer</h3>
        {packer ? (
          <>
            <div className="big">{packer.name}</div>
            <span className="badge">
              {packer.confidence.name} {packer.confidence.value}%
            </span>
          </>
        ) : (
          <div className="big muted">none</div>
        )}
      </div>

      <div className="card">
        <h3>Avg Entropy</h3>
        <div className="big">{avgEntropy(report).toFixed(2)}</div>
        <div className="muted">{report.imports.length} imports</div>
      </div>

      <div className="card">
        <h3>Hashes</h3>
        <div className="mono small" style={{ wordBreak: "break-all" }}>
          <div>SHA256 {id.sha256}</div>
          <div className="muted">SHA1 {id.sha1}</div>
          <div className="muted">MD5 {id.md5}</div>
        </div>
      </div>
    </div>
  );
}
