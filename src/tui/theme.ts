import { homedir } from "node:os";
import type { Severity } from "../types.js";

export const ACCENT = "#34d399";
export const ACCENT_2 = "#22d3ee";
export const DIM = "#6b7280";
export const FAINT = "#3f4654";
export const TEXT = "#e5e7eb";

export const SEV_COLOR: Record<Severity, string> = {
  critical: "#ff4d6d",
  high: "#ff8c42",
  medium: "#ffd166",
  low: "#8a94a6",
};

export const SEV_LABEL: Record<Severity, string> = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW" };

const LETTERS: Record<string, [string, string, string, string]> = {
  S: ["▗▄▄▖ ", "▐▌   ", " ▝▀▚▖", "▗▄▄▞▘"],
  H: ["▗▖ ▗▖", "▐▌ ▐▌", "▐▛▀▜▌", "▐▌ ▐▌"],
  I: ["▗▄▄▄▖", "  █  ", "  █  ", "▗▄█▄▖"],
  P: ["▗▄▄▖ ", "▐▌ ▐▌", "▐▛▀▘ ", "▐▌   "],
  C: [" ▗▄▄▖", "▐▌   ", "▐▌   ", "▝▚▄▄▖"],
  E: ["▗▄▄▄▖", "▐▌   ", "▐▛▀▀▘", "▐▙▄▄▖"],
  K: ["▗▖ ▗▖", "▐▌▗▞▘", "▐▛▚▖ ", "▐▌ ▐▌"],
};

/** Four-line block logo, 53 columns wide. */
export const LOGO: string[] = [0, 1, 2, 3].map((row) =>
  "SHIPCHECK"
    .split("")
    .map((ch) => (LETTERS[ch] as string[])[row])
    .join(" "),
);
export const LOGO_GRADIENT = ["#6ee7b7", "#34d399", "#2dd4bf", "#22d3ee"];

export const tilde = (p: string) => (p.startsWith(homedir()) ? `~${p.slice(homedir().length)}` : p);

export function truncate(s: string, n: number): string {
  if (n <= 1) return "";
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

/** Shorten from the left so the file name stays visible: `…/src/pay.ts`. */
export function truncateLeft(s: string, n: number): string {
  if (n <= 1) return "";
  return s.length > n ? `…${s.slice(s.length - n + 1)}` : s;
}
