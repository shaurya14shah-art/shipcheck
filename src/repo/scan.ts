import { execFileSync, spawn } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { contentHash, type Meter } from "../billing.js";
import { clientExposedSecrets, firebaseRules, sensitiveFile, sourcemapConfig, supabaseRls } from "../detectors/config.js";
import { secretFindings } from "../detectors/secrets.js";
import type { Finding, ScanResult } from "../types.js";

export interface RepoOptions {
  /** Also scan every historical version of every file. */
  history?: boolean;
  maxFileBytes?: number;
  /** Called as the scan advances, for live progress displays. */
  onProgress?: (p: Progress) => void;
}

export interface Progress {
  phase: string;
  done: number;
  total: number;
  findings: number;
}

/** Let the event loop breathe so an interactive UI can repaint during long scans. */
const tick = () => new Promise<void>((r) => setImmediate(r));

const SKIP_DIRS = /(^|\/)(node_modules|vendor|bower_components|\.git|\.venv|venv|__pycache__|\.next\/cache|Pods)\//;
const LOCKFILES = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|Cargo\.lock|poetry\.lock|Pipfile\.lock|Gemfile\.lock|composer\.lock|go\.sum|uv\.lock)$/;
const BINARY_EXT = /\.(png|jpe?g|gif|webp|avif|ico|icns|bmp|tiff?|psd|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|war|woff2?|ttf|otf|eot|mp[34]|m4a|mov|avi|webm|wav|ogg|flac|glb|gltf|fbx|obj|blend|bin|exe|dll|so|dylib|class|o|a|wasm|pyc|DS_Store|ttc|heic|svgz)$/i;
const CODE_OR_ENV = /(\.(js|jsx|ts|tsx|mjs|cjs|vue|svelte|astro)$)|(^|\/)\.env/;

const git = (cwd: string, args: string[]) => execFileSync("git", args, { cwd, maxBuffer: 1 << 30, stdio: ["ignore", "pipe", "ignore"] });

function isGitRepo(dir: string): string | null {
  try {
    return git(dir, ["rev-parse", "--show-toplevel"]).toString().trim();
  } catch {
    return null;
  }
}

function walk(root: string, dir = root, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const rel = relative(root, full);
    if (SKIP_DIRS.test(`${rel}/`)) continue;
    const st = statSync(full);
    if (st.isDirectory()) walk(root, full, out);
    else if (st.isFile()) out.push(rel);
  }
  return out;
}

const isBinary = (buf: Buffer) => buf.subarray(0, 8000).includes(0);
const skipContent = (path: string) => SKIP_DIRS.test(path) || LOCKFILES.test(path) || BINARY_EXT.test(path);

/** Run every content check on one file. */
function checkContent(path: string, text: string): Finding[] {
  const out = secretFindings(text, path);
  if (CODE_OR_ENV.test(path)) out.push(...clientExposedSecrets(text, path));
  out.push(...firebaseRules(text, path), ...sourcemapConfig(text, path));
  return out;
}

/** Stream `git cat-file --batch` so large histories never sit in memory at once. */
function readBlobs(cwd: string, shas: string[], onBlob: (sha: string, data: Buffer) => void): Promise<void> {
  return new Promise((resolve, reject) => {
    const proc = spawn("git", ["cat-file", "--batch"], { cwd, stdio: ["pipe", "pipe", "ignore"] });
    let buf = Buffer.alloc(0);
    proc.stdout.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      for (;;) {
        const nl = buf.indexOf(10);
        if (nl < 0) return;
        const header = buf.subarray(0, nl).toString();
        const [sha, type, sizeStr] = header.split(" ");
        if (type === "missing" || !sizeStr) {
          buf = buf.subarray(nl + 1);
          continue;
        }
        const size = Number(sizeStr);
        if (buf.length < nl + 1 + size + 1) return;
        onBlob(sha as string, buf.subarray(nl + 1, nl + 1 + size));
        buf = buf.subarray(nl + 1 + size + 1);
      }
    });
    proc.on("error", reject);
    proc.on("close", () => resolve());
    proc.stdin.end(shas.join("\n") + "\n");
  });
}

export async function scanRepo(target: string, meter: Meter, opts: RepoOptions = {}): Promise<ScanResult> {
  const maxBytes = opts.maxFileBytes ?? 2 * 1024 * 1024;
  // Stay scoped to the folder given, even when it sits inside a larger repository:
  // git commands run from `root` and only see paths beneath it.
  const root = target;
  const inGit = isGitRepo(target) !== null;
  const notes: string[] = [];
  const findings: Finding[] = [];
  let checked = 0;

  const list = (args: string[]) => git(root, ["ls-files", "-z", ...args]).toString().split("\0").filter(Boolean);
  const tracked = new Set(inGit ? list(["--cached"]) : []);
  // Not-ignored untracked files are what the next `git add .` would commit, so scan them too.
  const untracked = inGit ? list(["--others", "--exclude-standard"]) : [];
  const paths = inGit ? [...tracked, ...untracked] : walk(root);
  if (!inGit) notes.push("Not a git repository: scanned the folder as-is, history checks skipped.");

  const sqlFiles: Array<{ path: string; text: string }> = [];
  const currentValues = new Set<string>();

  const report = (phase: string, done: number, total: number) => opts.onProgress?.({ phase, done, total, findings: findings.length });
  report("Reading files", 0, paths.length);
  for (const [n, path] of paths.entries()) {
    if (n % 25 === 0) {
      report("Checking files", n, paths.length);
      await tick();
    }
    const sf = !inGit || tracked.has(path) ? sensitiveFile(path) : null;
    if (sf) findings.push(sf);
    if (skipContent(path)) continue;
    let buf: Buffer;
    try {
      const st = statSync(join(root, path));
      if (!st.isFile() || st.size > maxBytes) continue;
      buf = readFileSync(join(root, path));
    } catch {
      continue; // deleted in the working tree
    }
    if (isBinary(buf)) continue;
    checked++;
    meter.observe(contentHash(buf));
    const text = buf.toString("utf8");
    const found = checkContent(path, text);
    for (const f of found) if (f.evidence) currentValues.add(`${f.check}|${f.evidence}`);
    findings.push(...found);
    if (/(^|\/)supabase\/.*\.sql$/i.test(path)) sqlFiles.push({ path, text });
  }
  report("Checking files", paths.length, paths.length);
  findings.push(...supabaseRls(sqlFiles));

  if (inGit) {
    // .env files that are not ignored are one `git add .` away from being leaked.
    for (const p of untracked) {
      if (/(^|\/)\.env(\.|$)/.test(p) && !/\.env\.(example|sample|template|dist)$/.test(p)) {
        findings.push({
          check: "git/env-not-ignored",
          severity: "medium",
          title: ".env file is not git-ignored",
          fix: "Add `.env*` (and `!.env.example`) to .gitignore before someone commits it.",
          location: p,
        });
      }
    }
  }

  if (opts.history && inGit) {
    report("Reading git history", 0, 0);
    await tick();
    const current = new Set(
      git(root, ["ls-files", "-s", "-z"])
        .toString()
        .split("\0")
        .filter(Boolean)
        .map((l) => l.split(" ")[1] as string),
    );
    const objects = git(root, ["rev-list", "--all", "--objects", "--", "."]).toString().split("\n");
    const pathOf = new Map<string, string>();
    for (const line of objects) {
      const sp = line.indexOf(" ");
      if (sp < 0) continue;
      const sha = line.slice(0, sp);
      const p = line.slice(sp + 1);
      if (!current.has(sha) && !pathOf.has(sha) && !skipContent(p)) pathOf.set(sha, p);
    }
    // Only blobs (rev-list also lists trees, which have paths too); filter by type and size.
    const candidates = [...pathOf.keys()];
    const types = candidates.length
      ? execFileSync("git", ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"], {
          cwd: root,
          input: candidates.join("\n") + "\n",
          maxBuffer: 1 << 30,
        })
          .toString()
          .split("\n")
      : [];
    const blobs = types
      .map((l) => l.split(" "))
      .filter(([, type, size]) => type === "blob" && Number(size) <= maxBytes)
      .map(([sha]) => sha as string);

    let historyChecked = 0;
    await readBlobs(root, blobs, (sha, data) => {
      if (isBinary(data)) return;
      historyChecked++;
      if (historyChecked % 25 === 0) report("Scanning git history", historyChecked, blobs.length);
      meter.observe(contentHash(data));
      const path = pathOf.get(sha) as string;
      for (const f of secretFindings(data.toString("utf8"), path)) {
        // Still in the current files: already reported there.
        if (f.evidence && currentValues.has(`${f.check}|${f.evidence}`)) continue;
        findings.push({
          ...f,
          historyOnly: true,
          line: undefined,
          fix: `Deleted from the code but still in git history, so anyone with a clone has it. ${f.fix}`,
        });
      }
    });
    checked += historyChecked;
    notes.push(`History: ${historyChecked} past file versions checked across ${new Set(pathOf.values()).size} paths.`);
  }

  return {
    target: root,
    kind: "repo",
    findings: dedupe(findings),
    filesChecked: checked,
    billableFiles: meter.pendingCount,
    notes,
  };
}

function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.check}|${f.location}|${f.line ?? ""}|${f.evidence ?? ""}|${f.historyOnly ? "h" : ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
