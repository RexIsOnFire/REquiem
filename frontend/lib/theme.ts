// Shared color logic so every component reads verdict/severity/entropy the same
// way — mirrors the palette in requiem/report/html.py.

export const SEVERITY_COLOR: Record<string, string> = {
  INFO: "#5b6472",
  LOW: "#3b82f6",
  MEDIUM: "#eab308",
  HIGH: "#f97316",
  CRITICAL: "#ef4444",
};

export const VERDICT_COLOR: Record<string, string> = {
  malicious: "#ef4444",
  suspicious: "#eab308",
  benign: "#22c55e",
  unknown: "#6b7280",
};

// Heatmap cell shade by inferred-technique confidence.
export function confidenceShade(name: string): string {
  switch (name) {
    case "CERTAIN":
    case "HIGH":
      return "#7f1d1d";
    case "MEDIUM":
      return "#9a3412";
    case "LOW":
      return "#3f3f46";
    default:
      return "#262d3b";
  }
}

export function entropyColor(entropy: number): string {
  if (entropy >= 7.2) return "#ef4444";
  if (entropy >= 6) return "#eab308";
  return "#22c55e";
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
