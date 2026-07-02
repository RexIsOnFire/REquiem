import type { DynamicBehavior, ProcessNode } from "@/lib/types";

function TreeNode({ node, depth }: { node: ProcessNode; depth: number }) {
  return (
    <div>
      <div
        className="mono"
        style={{ padding: "2px 0", paddingLeft: depth * 22, whiteSpace: "nowrap" }}
      >
        <span className="muted">{depth > 0 ? "└─ " : ""}</span>
        <b>{node.name}</b>{" "}
        <span className="muted">#{node.pid}</span>{" "}
        {node.cmdline && node.cmdline !== node.name && (
          <span className="muted">{node.cmdline}</span>
        )}
      </div>
      {node.children.map((c, i) => (
        <TreeNode key={`${c.pid}-${i}`} node={c} depth={depth + 1} />
      ))}
    </div>
  );
}

function KVList({
  title,
  rows,
}: {
  title: string;
  rows: Record<string, unknown>[];
}) {
  if (rows.length === 0) return null;
  return (
    <div className="card" style={{ marginTop: 12 }}>
      <h3>{title}</h3>
      <ul className="mono small" style={{ margin: 0, paddingLeft: 16 }}>
        {rows.map((r, i) => (
          <li key={i}>
            {Object.entries(r)
              .map(([k, v]) => `${k}=${String(v)}`)
              .join("  ")}
          </li>
        ))}
      </ul>
    </div>
  );
}

export function ProcessTree({ dynamic }: { dynamic: DynamicBehavior }) {
  if (!dynamic.executed) {
    return <p className="muted">Dynamic analysis was not run.</p>;
  }
  return (
    <div>
      <div style={{ marginBottom: 10 }}>
        {dynamic.simulated ? (
          <span
            className="badge"
            style={{ background: "#7c4a03", color: "#ffd7a1", borderColor: "#7c4a03" }}
          >
            SIMULATED · {dynamic.backend}
          </span>
        ) : (
          <span
            className="badge"
            style={{ background: "#7f1d1d", color: "#fecaca", borderColor: "#7f1d1d" }}
          >
            LIVE SANDBOX · {dynamic.backend}
          </span>
        )}
      </div>

      <div className="card scroll">
        <h3>Process Tree</h3>
        {dynamic.process_tree.length > 0 ? (
          dynamic.process_tree.map((n, i) => <TreeNode key={i} node={n} depth={0} />)
        ) : (
          <span className="muted">—</span>
        )}
      </div>

      <KVList title="Network" rows={dynamic.network} />
      <KVList title="Filesystem" rows={dynamic.filesystem} />
      <KVList title="Registry" rows={dynamic.registry} />
    </div>
  );
}
