import type { SectionInfo } from "@/lib/types";
import { entropyColor } from "@/lib/theme";

function EntropyBar({ entropy }: { entropy: number }) {
  const pct = Math.min(100, (entropy / 8) * 100);
  return (
    <span>
      <span className="bar">
        <span
          className="fill"
          style={{ width: `${pct}%`, background: entropyColor(entropy) }}
        />
      </span>
      <span className="mono">{entropy.toFixed(2)}</span>
    </span>
  );
}

export function SectionsView({ sections }: { sections: SectionInfo[] }) {
  if (sections.length === 0) return <p className="muted">No sections parsed.</p>;
  return (
    <div className="scroll">
      <table>
        <thead>
          <tr>
            <th>Section</th>
            <th>Entropy</th>
            <th>Raw size</th>
            <th>Virtual size</th>
            <th>Flags</th>
          </tr>
        </thead>
        <tbody>
          {sections.slice(0, 60).map((s, i) => (
            <tr key={`${s.name}-${i}`}>
              <td className="mono">{s.name || "(unnamed)"}</td>
              <td>
                <EntropyBar entropy={s.entropy} />
              </td>
              <td className="mono">{s.raw_size.toLocaleString()}</td>
              <td className="mono muted">{s.virtual_size.toLocaleString()}</td>
              <td className="mono muted small">{s.characteristics.join(" ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
