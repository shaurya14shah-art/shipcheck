import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Severity } from "../types.js";

export interface RecentScan {
  kind: "repo" | "url";
  target: string;
  history: boolean;
  at: number;
  counts: Partial<Record<Severity, number>>;
}

const file = () => join(process.env.SHIPCHECK_HOME ?? join(homedir(), ".shipcheck"), "recent.json");

export function loadRecent(): RecentScan[] {
  try {
    return (JSON.parse(readFileSync(file(), "utf8")) as RecentScan[]).slice(0, 5);
  } catch {
    return [];
  }
}

export function saveRecent(scan: RecentScan): void {
  const list = [scan, ...loadRecent().filter((r) => !(r.kind === scan.kind && r.target === scan.target))].slice(0, 5);
  try {
    mkdirSync(join(file(), ".."), { recursive: true });
    writeFileSync(file(), JSON.stringify(list, null, 2));
  } catch {
    /* recents are a convenience only */
  }
}

export function ago(ts: number): string {
  const s = Math.round((Date.now() - ts) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}
