import { contentHash, type Meter } from "../billing.js";
import { jwtPayload, secretFindings } from "../detectors/secrets.js";
import type { Finding, ScanResult } from "../types.js";
import { checkOwnership, isLocal, WELL_KNOWN } from "./verify.js";

export interface UrlOptions {
  /** Run ownership-gated checks (exposed files, open databases). */
  active?: boolean;
  maxAssets?: number;
  timeoutMs?: number;
  onProgress?: (p: { phase: string; done: number; total: number; findings: number }) => void;
}

interface Fetched {
  status: number;
  url: string;
  headers: Headers;
  text: string;
}

const UA = "shipcheck/0.1 (+security self-check)";
const MAX_BODY = 8 * 1024 * 1024;

async function get(url: string, timeoutMs: number, init: RequestInit = {}): Promise<Fetched> {
  const res = await fetch(url, { redirect: "follow", ...init, headers: { "user-agent": UA, ...(init.headers ?? {}) }, signal: AbortSignal.timeout(timeoutMs) });
  const buf = Buffer.from(await res.arrayBuffer());
  return { status: res.status, url: res.url || url, headers: res.headers, text: buf.subarray(0, MAX_BODY).toString("utf8") };
}

const siteOf = (host: string) => host.split(".").slice(-2).join(".");
const looksHtml = (t: string) => /^\s*(<!doctype html|<html|<head|<body)/i.test(t);

function headerFindings(page: Fetched): Finding[] {
  const h = page.headers;
  const at = page.url;
  const out: Finding[] = [];
  const https = at.startsWith("https:");
  const csp = h.get("content-security-policy") ?? "";
  const add = (check: string, severity: Finding["severity"], title: string, fix: string, evidence?: string) =>
    out.push({ check: `web/${check}`, severity, title, fix, location: at, evidence });

  if (!csp) add("no-csp", "medium", "No Content-Security-Policy", "Add a CSP header. It is the main defence if an attacker gets script onto your page.");
  if (https && !h.get("strict-transport-security")) add("no-hsts", "medium", "No HSTS header", "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains`.");
  if (!h.get("x-content-type-options")) add("no-nosniff", "low", "No X-Content-Type-Options", "Add `X-Content-Type-Options: nosniff`.");
  if (!h.get("x-frame-options") && !/frame-ancestors/i.test(csp)) add("frameable", "low", "Page can be framed (clickjacking)", "Add `frame-ancestors 'self'` to your CSP or `X-Frame-Options: DENY`.");
  const powered = [h.get("x-powered-by"), h.get("server")].filter((v): v is string => !!v && /\d/.test(v));
  if (powered.length) add("version-disclosure", "low", "Server software version disclosed", "Hide version numbers so attackers cannot match you to known exploits.", powered.join(", "));

  for (const raw of h.getSetCookie()) {
    const name = raw.split("=")[0]?.trim() ?? "cookie";
    const attrs = raw.toLowerCase();
    const issues: string[] = [];
    const sensitive = /sess|auth|token|jwt|sid|login/i.test(name);
    if (https && !/;\s*secure/.test(attrs)) issues.push("no Secure");
    if (sensitive && !/;\s*httponly/.test(attrs)) issues.push("no HttpOnly");
    if (!/;\s*samesite=/.test(attrs)) issues.push("no SameSite");
    if (issues.length) {
      add(
        "cookie-flags",
        sensitive && issues.some((i) => i !== "no SameSite") ? "medium" : "low",
        `Cookie "${name}" missing flags`,
        "Set Secure, HttpOnly (for session cookies) and SameSite=Lax on cookies.",
        issues.join(", "),
      );
    }
  }
  return out;
}

/** Same-site script URLs referenced by an HTML page. */
function scriptRefs(html: string, base: string): string[] {
  const refs: string[] = [];
  for (const m of html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)) refs.push(m[1] as string);
  for (const m of html.matchAll(/<link\b[^>]*>/gi)) {
    const tag = m[0];
    if (/rel\s*=\s*["']?(modulepreload|preload)/i.test(tag) && (/as\s*=\s*["']?script/i.test(tag) || /modulepreload/i.test(tag))) {
      const href = /href\s*=\s*["']([^"']+)["']/i.exec(tag)?.[1];
      if (href) refs.push(href);
    }
  }
  return refs.map((r) => new URL(r, base).toString());
}

/** Chunks a bundle imports, so lazily-loaded code is checked too. */
function chunkRefs(js: string, base: string): string[] {
  const refs = new Set<string>();
  for (const m of js.matchAll(/(?:import\(|from\s*|import\s*)["'`](\.{1,2}\/[^"'`]+?\.m?js)["'`]/g)) refs.add(new URL(m[1] as string, base).toString());
  for (const m of js.matchAll(/["'`](\/?(?:assets|_next\/static\/chunks|static\/js)\/[^"'`\s]+?\.m?js)["'`]/g)) refs.add(new URL(m[1] as string, base).toString());
  return [...refs];
}

interface Backends {
  supabase: Map<string, string>; // project url -> public key
  firebaseDbs: Set<string>;
}

function collectBackends(text: string, into: Backends): void {
  const urls = [...text.matchAll(/https:\/\/([a-z0-9]{20})\.supabase\.co/g)].map((m) => `https://${m[1]}.supabase.co`);
  if (urls.length) {
    const jwtKeys = [...text.matchAll(/\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g)].map((m) => m[0]).filter((k) => jwtPayload(k)?.role === "anon");
    const pubKeys = [...text.matchAll(/\bsb_publishable_[A-Za-z0-9_-]{20,}/g)].map((m) => m[0]);
    const key = jwtKeys[0] ?? pubKeys[0];
    for (const u of urls) if (key && !into.supabase.has(u)) into.supabase.set(u, key);
  }
  for (const m of text.matchAll(/https:\/\/[a-z0-9-]+\.(?:firebaseio\.com|[a-z0-9-]+\.firebasedatabase\.app)/g)) into.firebaseDbs.add(m[0]);
}

export async function scanUrl(input: string, meter: Meter, opts: UrlOptions = {}): Promise<ScanResult> {
  const timeout = opts.timeoutMs ?? 10_000;
  const maxAssets = opts.maxAssets ?? 60;
  const start = /^https?:\/\//i.test(input) ? input : `https://${input}`;
  const findings: Finding[] = [];
  const notes: string[] = [];
  let checked = 0;
  const observe = (text: string) => {
    checked++;
    meter.observe(contentHash(text));
  };

  const report = (phase: string, done = 0, total = 0) => opts.onProgress?.({ phase, done, total, findings: findings.length });
  report("Loading page");
  const page = await get(start, timeout);
  if (page.status >= 400) throw new Error(`${start} returned HTTP ${page.status}`);
  observe(page.text);
  const origin = new URL(page.url).origin;
  const host = new URL(page.url).hostname;
  findings.push(...headerFindings(page));

  // Plain-HTTP access should redirect to HTTPS.
  if (page.url.startsWith("https:") && !isLocal(host)) {
    try {
      const plain = await get(`http://${new URL(page.url).host}/`, timeout, { redirect: "manual" });
      if (plain.status >= 200 && plain.status < 300) {
        findings.push({ check: "web/no-https-redirect", severity: "medium", title: "Site still serves plain HTTP", fix: "Redirect all http:// requests to https://.", location: `http://${host}/` });
      }
    } catch {
      /* port 80 closed is fine */
    }
  }

  const backends: Backends = { supabase: new Map(), firebaseDbs: new Set() };
  // Inline scripts.
  for (const m of page.text.matchAll(/<script\b(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)) {
    findings.push(...secretFindings(m[1] as string, `${page.url} (inline script)`).map((f) => ({ ...f, line: undefined })));
  }
  collectBackends(page.text, backends);

  // A script is often referenced twice (modulepreload + <script>); fetch and bill it once.
  const queue = [...new Set(scriptRefs(page.text, page.url).filter((u) => siteOf(new URL(u).hostname) === siteOf(host)))];
  const seen = new Set(queue);
  let exposedMaps = 0;
  const mapExamples: string[] = [];

  const checkMap = async (mapUrl: string) => {
    try {
      const r = await get(mapUrl, timeout);
      if (r.status !== 200 || looksHtml(r.text)) return;
      const map = JSON.parse(r.text) as { sources?: string[]; sourcesContent?: unknown[] };
      if (!Array.isArray(map.sources) || map.sources.length === 0) return;
      observe(r.text);
      exposedMaps++;
      const own = map.sources.filter((s) => !/node_modules|webpack\/runtime|vite\/|\(webpack\)/.test(s));
      if (mapExamples.length < 3 && own[0]) mapExamples.push(own[0].replace(/^(webpack:\/\/\/|\.\.\/)+/, ""));
    } catch {
      /* not a map */
    }
  };

  let i = 0;
  while (i < queue.length && i < maxAssets) {
    const batch = queue.slice(i, Math.min(queue.length, maxAssets, i + 6));
    i += batch.length;
    report("Checking scripts", i, Math.min(queue.length, maxAssets));
    await Promise.all(
      batch.map(async (url) => {
        let r: Fetched;
        try {
          r = await get(url, timeout);
        } catch {
          return;
        }
        if (r.status !== 200 || looksHtml(r.text)) return;
        observe(r.text);
        findings.push(...secretFindings(r.text, url).map((f) => ({ ...f, line: undefined })));
        collectBackends(r.text, backends);
        const mapRef = /\/\/[#@]\s*sourceMappingURL=(\S+)\s*$/.exec(r.text)?.[1];
        if (mapRef && !mapRef.startsWith("data:")) await checkMap(new URL(mapRef, url).toString());
        for (const next of chunkRefs(r.text, url)) {
          if (!seen.has(next) && siteOf(new URL(next).hostname) === siteOf(host)) {
            seen.add(next);
            queue.push(next);
          }
        }
      }),
    );
  }
  if (queue.length > maxAssets) notes.push(`Checked the first ${maxAssets} of ${queue.length} scripts (raise with --max-assets).`);
  if (exposedMaps) {
    findings.push({
      check: "web/public-sourcemaps",
      severity: "high",
      title: "Your source code is public via source maps",
      fix: "Stop deploying .map files publicly (Vite: `build.sourcemap: 'hidden'`, Next.js: remove productionBrowserSourceMaps).",
      location: origin,
      evidence: `${exposedMaps} map file${exposedMaps === 1 ? "" : "s"}${mapExamples.length ? `, e.g. ${mapExamples.join(", ")}` : ""}`,
    });
  }

  if (!opts.active) {
    if (backends.supabase.size || backends.firebaseDbs.size) {
      notes.push("Found a Supabase/Firebase backend. Run `shipcheck verify` then `--active` to test which data anyone can read.");
    }
  } else {
    report("Verifying ownership");
    const owner = await checkOwnership(origin, (u) => get(u, timeout));
    if (!owner.ok) {
      throw new Error(`Active checks need proof you own ${host}. Serve this text at ${origin}${WELL_KNOWN}:\n\n  ${owner.token}\n`);
    }
    report("Probing for exposed files");
    findings.push(...(await exposedFiles(origin, timeout, observe)));
    report("Testing database access");
    findings.push(...(await openSupabase(backends.supabase, timeout)));
    findings.push(...(await openFirebase(backends.firebaseDbs, timeout)));
  }

  return { target: page.url, kind: "url", findings, filesChecked: checked, billableFiles: meter.pendingCount, notes };
}

async function exposedFiles(origin: string, timeout: number, observe: (t: string) => void): Promise<Finding[]> {
  const out: Finding[] = [];
  // Single-page apps answer every path with index.html; remember that body so it is not mistaken for a leak.
  let fallback = "";
  try {
    fallback = (await get(`${origin}/shipcheck-${Date.now()}-does-not-exist`, timeout)).text;
  } catch {
    /* ignore */
  }
  const probes: Array<{ path: string; test: (t: string) => string | null; title: string; fix: string }> = [
    ...[".env", ".env.local", ".env.production"].map((p) => ({
      path: `/${p}`,
      test: (t: string) => {
        const names = [...t.matchAll(/^\s*([A-Z][A-Z0-9_]{2,})\s*=/gm)].map((m) => m[1] as string);
        return names.length ? `variables: ${names.slice(0, 6).join(", ")}${names.length > 6 ? ", …" : ""}` : null;
      },
      title: "Environment file downloadable",
      fix: "Block dotfiles in your web server or hosting config, then rotate every secret in the file.",
    })),
    { path: "/.git/HEAD", test: (t) => (/^ref: refs\//.test(t) ? "repository HEAD readable" : null), title: "Git repository downloadable", fix: "Your full source and history can be downloaded. Block /.git in the server config and redeploy without it." },
    { path: "/.git/config", test: (t) => (/\[core\]/.test(t) ? "git config readable" : null), title: "Git config downloadable", fix: "Block /.git in the server config." },
  ];
  for (const p of probes) {
    try {
      const r = await get(origin + p.path, timeout);
      if (r.status !== 200 || r.text === fallback || looksHtml(r.text)) continue;
      const ev = p.test(r.text);
      if (!ev) continue;
      observe(r.text);
      out.push({ check: `web/exposed${p.path.replace(/[^a-z]+/gi, "-")}`, severity: "critical", title: p.title, fix: p.fix, location: origin + p.path, evidence: ev });
    } catch {
      /* unreachable */
    }
  }
  return out;
}

export async function openSupabase(projects: Map<string, string>, timeout: number): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const [base, key] of projects) {
    const headers: Record<string, string> = { apikey: key };
    if (key.startsWith("eyJ")) headers.authorization = `Bearer ${key}`;
    let tables: string[] = [];
    try {
      const spec = await get(`${base}/rest/v1/`, timeout, { headers });
      if (spec.status !== 200) continue;
      const paths = (JSON.parse(spec.text) as { paths?: Record<string, unknown> }).paths ?? {};
      tables = Object.keys(paths)
        .filter((p) => p !== "/" && !p.startsWith("/rpc/"))
        .map((p) => p.slice(1))
        .slice(0, 50);
    } catch {
      continue;
    }
    for (const t of tables) {
      try {
        const r = await get(`${base}/rest/v1/${encodeURIComponent(t)}?select=*&limit=1`, timeout, { headers: { ...headers, prefer: "count=estimated" } });
        if (r.status !== 200) continue;
        const rows = JSON.parse(r.text) as unknown;
        if (!Array.isArray(rows) || rows.length === 0) continue;
        const total = r.headers.get("content-range")?.split("/")[1];
        out.push({
          check: "supabase/table-readable",
          severity: "critical",
          title: "Database table readable by anyone",
          fix: `Enable row level security on "${t}" and add a policy limiting who can read it. Your anon key ships in the frontend, so this data is public.`,
          location: `${base}/rest/v1/${t}`,
          // Never echo row data: report only that rows are readable, and roughly how many.
          evidence: total && total !== "*" ? `about ${Number(total).toLocaleString()} rows exposed` : "rows exposed",
        });
      } catch {
        /* skip table */
      }
    }
  }
  return out;
}

async function openFirebase(dbs: Set<string>, timeout: number): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const db of dbs) {
    try {
      const r = await get(`${db}/.json?shallow=true`, timeout);
      if (r.status === 200 && r.text.trim() !== "null") {
        out.push({
          check: "firebase/database-readable",
          severity: "critical",
          title: "Firebase database readable by anyone",
          fix: 'Change the Realtime Database rules so ".read" requires auth.',
          location: db,
          // Key names can be user ids, so report only how many there are.
          evidence: `${Object.keys(JSON.parse(r.text) as object).length} top-level keys readable`,
        });
      }
    } catch {
      /* closed */
    }
  }
  return out;
}
