import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const dir = () => process.env.SHIPCHECK_HOME ?? join(homedir(), ".shipcheck");
const file = () => join(dir(), "verify.json");

function load(): Record<string, string> {
  try {
    return JSON.parse(readFileSync(file(), "utf8")) as Record<string, string>;
  } catch {
    return {};
  }
}

export const WELL_KNOWN = "/.well-known/shipcheck.txt";

/** The ownership token for a host, created on first request. */
export function tokenFor(host: string): string {
  const all = load();
  if (!all[host]) {
    all[host] = `shipcheck-verify-${randomBytes(12).toString("hex")}`;
    mkdirSync(dir(), { recursive: true });
    writeFileSync(file(), JSON.stringify(all, null, 2));
  }
  return all[host] as string;
}

export const isLocal = (host: string) => /^(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)$/.test(host) || host.endsWith(".localhost") || host.endsWith(".test");

/**
 * Active checks only run against sites the user controls: they must publish their token at
 * /.well-known/shipcheck.txt. Local development hosts are always allowed.
 */
export async function checkOwnership(origin: string, fetchText: (u: string) => Promise<{ status: number; text: string }>): Promise<{ ok: boolean; token: string }> {
  const host = new URL(origin).host;
  const hostname = new URL(origin).hostname;
  const token = tokenFor(host);
  if (isLocal(hostname)) return { ok: true, token };
  try {
    const r = await fetchText(origin + WELL_KNOWN);
    return { ok: r.status === 200 && r.text.includes(token), token };
  } catch {
    return { ok: false, token };
  }
}
