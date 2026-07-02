// Memory-visualization palette. Colors are the pre-validated reference
// categorical hues (dark mode) — see the dataviz skill's validator, which
// passes all six checks against these on the ReQuiem dark surface. Region
// identity is ALSO carried by a text label on every block, so color is never
// the sole channel.
import type { MemoryRegion } from "./types";

export const KIND_COLOR: Record<string, string> = {
  image: "#3987e5", // blue    — file/DLL-backed code & data
  mapped: "#199e70", // aqua   — mapped views
  stack: "#c98500", // yellow  — thread stacks
  private: "#9085e9", // violet — private commits
  heap: "#3987e5", // blue-ish
  shellcode: "#d03b3b", // critical status red — unbacked exec
};

// Status color, reserved — used only to flag suspicious regions, always with
// the ⚠ label beside it.
export const SUSPICIOUS = "#d03b3b";

export function kindColor(r: MemoryRegion): string {
  if (r.suspicious && r.kind !== "shellcode") return SUSPICIOUS;
  return KIND_COLOR[r.kind] ?? "#8b94a7";
}

export function hexAddr(n: number): string {
  // Numbers this large lose precision as JS doubles beyond 2^53, but sandbox
  // base addresses fit; format defensively all the same.
  return "0x" + Math.round(n).toString(16).padStart(12, "0");
}

export function humanBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${Math.round(n / 1024)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(n < 10 * 1024 * 1024 ? 1 : 0)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(1)} GB`;
}
