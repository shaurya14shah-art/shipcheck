import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Pricing: pay per file checked, charged to the company.
 *
 * - A "file" is one unique piece of content: a repo file, a historical version of a file,
 *   or a web asset fetched during a URL scan (HTML page, JS bundle, source map).
 * - Content is identified by its SHA-256. Re-scanning content you already paid for is free,
 *   so CI runs on every push only cost the files that changed.
 * - The first FREE_FILES each month are free, so anyone can try it on a real repo.
 */
export const PRICING = {
  currency: "USD",
  freeFilesPerMonth: 2_500,
  /** $2.00 per 1,000 files. */
  perFile: 0.002,
  /** Volume rate for every file past 1M in a month: $1.00 per 1,000. */
  volumeThreshold: 1_000_000,
  volumePerFile: 0.001,
} as const;

export function contentHash(data: string | Buffer): string {
  // 64 bits of SHA-256 is plenty to dedupe content for one organisation.
  return createHash("sha256").update(data).digest("hex").slice(0, 16);
}

export interface Bill {
  billableFiles: number;
  freeFiles: number;
  paidFiles: number;
  usd: number;
  usedThisMonthAfter: number;
}

/** Price `files` new files given how many were already used this month. */
export function price(files: number, usedThisMonth: number): Bill {
  const freeLeft = Math.max(0, PRICING.freeFilesPerMonth - usedThisMonth);
  const freeFiles = Math.min(files, freeLeft);
  const paidFiles = files - freeFiles;
  const paidStart = Math.max(usedThisMonth, PRICING.freeFilesPerMonth);
  // Files before the volume threshold at the standard rate, the rest at the volume rate.
  const standard = Math.max(0, Math.min(paidFiles, PRICING.volumeThreshold - paidStart));
  const volume = paidFiles - standard;
  const usd = Math.round((standard * PRICING.perFile + volume * PRICING.volumePerFile) * 100) / 100;
  return { billableFiles: files, freeFiles, paidFiles, usd, usedThisMonthAfter: usedThisMonth + files };
}

interface MeterState {
  month: string;
  used: number;
  seen: string[];
}

const thisMonth = () => new Date().toISOString().slice(0, 7);

/**
 * Local meter. Records content hashes (never content) so unchanged files are not billed twice.
 * The hosted meter will keep the same hashes per organisation server-side.
 */
export class Meter {
  private seen: Set<string>;
  private pending = new Set<string>();
  private used: number;
  private month: string;
  private readonly file: string;

  constructor(dir = process.env.SHIPCHECK_HOME ?? join(homedir(), ".shipcheck")) {
    this.file = join(dir, "meter.json");
    let state: MeterState = { month: thisMonth(), used: 0, seen: [] };
    try {
      state = JSON.parse(readFileSync(this.file, "utf8")) as MeterState;
    } catch {
      /* first run */
    }
    this.seen = new Set(state.seen);
    this.month = state.month;
    this.used = state.month === thisMonth() ? state.used : 0;
    if (state.month !== thisMonth()) this.month = thisMonth();
    mkdirSync(dir, { recursive: true });
  }

  /** Register content; returns true if it is new (billable). */
  observe(hash: string): boolean {
    if (this.seen.has(hash) || this.pending.has(hash)) return false;
    this.pending.add(hash);
    return true;
  }

  get pendingCount(): number {
    return this.pending.size;
  }

  /** Free files left this month before this scan's pending files. */
  get freeLeft(): number {
    return Math.max(0, PRICING.freeFilesPerMonth - this.used);
  }

  quote(): Bill {
    return price(this.pending.size, this.used);
  }

  /** Persist the scan's new hashes and usage. Skipped for estimates. */
  commit(): Bill {
    const bill = this.quote();
    for (const h of this.pending) this.seen.add(h);
    this.used = bill.usedThisMonthAfter;
    this.pending.clear();
    const tmp = `${this.file}.tmp`;
    writeFileSync(tmp, JSON.stringify({ month: this.month, used: this.used, seen: [...this.seen] } satisfies MeterState));
    renameSync(tmp, this.file);
    return bill;
  }
}
