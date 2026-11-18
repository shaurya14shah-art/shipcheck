import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { Meter, price, PRICING } from "../src/billing.js";
import { toSarif } from "../src/report.js";
import { scanRepo } from "../src/repo/scan.js";
import { openSupabase, scanUrl } from "../src/url/scan.js";
import { FAKE, tempDir } from "./helpers.js";

beforeEach(() => {
  process.env.SHIPCHECK_HOME = tempDir("shipcheck-home-");
});

describe("pricing", () => {
  it("gives the free allowance first, then bills per file", () => {
    expect(price(1000, 0).usd).toBe(0);
    expect(price(3500, 0)).toMatchObject({ freeFiles: 2500, paidFiles: 1000, usd: 2 });
    expect(price(1000, 5000)).toMatchObject({ freeFiles: 0, paidFiles: 1000, usd: 2 });
  });
  it("switches to the volume rate past the threshold", () => {
    const b = price(1000, PRICING.volumeThreshold - 500);
    expect(b.usd).toBe(500 * PRICING.perFile + 500 * PRICING.volumePerFile);
  });
  it("never bills the same content twice, across runs", () => {
    const m1 = new Meter();
    expect(m1.observe("aa")).toBe(true);
    expect(m1.observe("aa")).toBe(false);
    m1.commit();
    const m2 = new Meter();
    expect(m2.observe("aa")).toBe(false);
    expect(m2.observe("bb")).toBe(true);
    expect(m2.quote().billableFiles).toBe(1);
  });
});

const sh = (cwd: string, ...args: string[]) => execFileSync("git", args, { cwd, stdio: "ignore" });

describe("repo scan", () => {
  let repo: string;
  beforeAll(() => {
    repo = tempDir("shipcheck-repo-");
    sh(repo, "init", "-q");
    sh(repo, "config", "user.email", "t@example.com");
    sh(repo, "config", "user.name", "t");
    mkdirSync(join(repo, "src"));
    mkdirSync(join(repo, "supabase/migrations"), { recursive: true });
    mkdirSync(join(repo, "node_modules/pkg"), { recursive: true });
    writeFileSync(join(repo, "src/pay.ts"), `export const key = "${FAKE.stripeLive}";\n`);
    writeFileSync(join(repo, "src/old.ts"), `const gh = "${FAKE.github}";\n`);
    writeFileSync(join(repo, ".env.production"), `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=${FAKE.serviceRole}\n`);
    writeFileSync(join(repo, "supabase/migrations/1.sql"), "create table notes (id int);\n");
    writeFileSync(join(repo, "logo.png"), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 0, 0, 0]));
    writeFileSync(join(repo, "node_modules/pkg/index.js"), `x="${FAKE.aws}"`);
    writeFileSync(join(repo, ".gitignore"), "node_modules\n");
    sh(repo, "add", "-A");
    sh(repo, "commit", "-qm", "init");
    // Remove the GitHub token from the code: it should still be found in history.
    writeFileSync(join(repo, "src/old.ts"), "const gh = process.env.GH_TOKEN;\n");
    sh(repo, "commit", "-qam", "remove token");
    // An untracked, un-ignored .env that the next `git add .` would leak.
    writeFileSync(join(repo, ".env"), `OPENAI_API_KEY=${FAKE.openai}\n`);
  });

  it("finds current problems and skips vendored, binary and ignored content", async () => {
    const r = await scanRepo(repo, new Meter());
    const got = r.findings.map((f) => `${f.check} ${f.location}`).sort();
    expect(got).toEqual(
      [
        "config/client-exposed-secret .env.production",
        "file/environment-file-committed .env.production",
        "git/env-not-ignored .env",
        "secret/openai .env",
        "secret/stripe-live src/pay.ts",
        "secret/supabase-service-role .env.production",
        "supabase/rls-disabled supabase/migrations/1.sql",
      ].sort(),
    );
    expect(r.findings.some((f) => f.location.includes("node_modules"))).toBe(false);
  });

  it("finds a secret that only survives in git history", async () => {
    const r = await scanRepo(repo, new Meter(), { history: true });
    const hist = r.findings.filter((f) => f.historyOnly);
    expect(hist.map((f) => `${f.check} ${f.location}`)).toEqual(["secret/github-token src/old.ts"]);
    // The live Stripe key is in current files, so it is not reported a second time from history.
    expect(r.findings.filter((f) => f.check === "secret/stripe-live")).toHaveLength(1);
  });

  it("bills only new content: an unchanged re-scan is free", async () => {
    const first = new Meter();
    const r1 = await scanRepo(repo, first);
    expect(r1.billableFiles).toBe(r1.filesChecked);
    first.commit();
    const second = new Meter();
    const r2 = await scanRepo(repo, second);
    expect(r2.billableFiles).toBe(0);
    writeFileSync(join(repo, "src/new.ts"), "export const x = 1;\n");
    const third = await scanRepo(repo, new Meter());
    expect(third.billableFiles).toBe(1);
  });

  it("writes valid SARIF", async () => {
    const r = await scanRepo(repo, new Meter());
    const s = toSarif(r) as { runs: Array<{ results: Array<{ ruleId: string; level: string }> }> };
    expect(s.runs[0]!.results.find((x) => x.ruleId === "secret/stripe-live")?.level).toBe("error");
  });
});

describe("url scan", () => {
  let server: Server;
  let base: string;
  const bundle = `const s="${FAKE.serviceRole}";import("./chunk-a.js");\n//# sourceMappingURL=app.js.map`;
  const chunk = `export const k="${FAKE.stripeLive}";`;
  const map = JSON.stringify({ version: 3, sources: ["../src/App.tsx", "../node_modules/react/index.js"], mappings: "" });
  const html = `<!doctype html><html><head><link rel="modulepreload" href="/assets/app.js"><script type="module" src="/assets/app.js"></script><script src="https://cdn.other.com/x.js"></script></head><body><script>window.cfg={k:"${FAKE.github}"}</script></body></html>`;

  beforeAll(async () => {
    server = createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://x");
      const send = (status: number, body: string, headers: Record<string, string | string[]> = {}) => {
        res.writeHead(status, headers);
        res.end(body);
      };
      if (url.pathname === "/") return send(200, html, { "content-type": "text/html", "set-cookie": ["session=abc; Path=/"], "x-powered-by": "Express 4.18.2" });
      if (url.pathname === "/assets/app.js") return send(200, bundle, { "content-type": "text/javascript" });
      if (url.pathname === "/assets/chunk-a.js") return send(200, chunk);
      if (url.pathname === "/assets/app.js.map") return send(200, map);
      if (url.pathname === "/.env") return send(200, `DATABASE_URL=${FAKE.dbUrl}\nSTRIPE_SECRET=${FAKE.stripeLive}\n`);
      // Supabase REST emulation for the open-table check.
      if (url.pathname === "/rest/v1/") return send(200, JSON.stringify({ paths: { "/": {}, "/profiles": {}, "/secrets": {}, "/rpc/fn": {} } }));
      if (url.pathname === "/rest/v1/profiles") return send(200, JSON.stringify([{ id: 1, email: "person@example.com" }]), { "content-range": "0-0/1532" });
      if (url.pathname === "/rest/v1/secrets") return send(200, "[]");
      // Everything else behaves like a single-page app: index.html with 200.
      return send(200, html, { "content-type": "text/html" });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(() => server.close());

  it("finds keys in bundles, lazy chunks and inline scripts, and public source maps", async () => {
    const r = await scanUrl(base, new Meter());
    const checks = r.findings.map((f) => f.check);
    expect(checks).toEqual(expect.arrayContaining(["secret/supabase-service-role", "secret/stripe-live", "secret/github-token", "web/public-sourcemaps", "web/no-csp", "web/version-disclosure", "web/cookie-flags"]));
    expect(r.findings.find((f) => f.check === "web/public-sourcemaps")?.evidence).toMatch(/1 map file, e\.g\. src\/App\.tsx/);
    expect(r.findings.find((f) => f.check === "web/cookie-flags")?.severity).toBe("medium");
    // Passive scans never probe for files.
    expect(checks.some((c) => c.startsWith("web/exposed"))).toBe(false);
    // Third-party scripts are not fetched; page + 2 scripts + 1 map are billed.
    expect(r.filesChecked).toBe(4);
  });

  it("active mode finds a downloadable .env without being fooled by the SPA fallback", async () => {
    const r = await scanUrl(base, new Meter(), { active: true });
    const exposed = r.findings.filter((f) => f.check.startsWith("web/exposed"));
    expect(exposed.map((f) => f.location)).toEqual([`${base}/.env`]);
    expect(exposed[0]!.evidence).toBe("variables: DATABASE_URL, STRIPE_SECRET");
    expect(JSON.stringify(exposed)).not.toContain(FAKE.stripeLive);
  });

  it("refuses active checks on a site the user has not verified", async () => {
    await expect(scanUrl("http://example.invalid", new Meter(), { active: true, timeoutMs: 500 })).rejects.toThrow();
  });

  it("reports Supabase tables that return rows, without echoing data", async () => {
    const f = await openSupabase(new Map([[base, FAKE.anon]]), 5000);
    expect(f.map((x) => x.location)).toEqual([`${base}/rest/v1/profiles`]);
    expect(f[0]!.evidence).toBe("about 1,532 rows exposed");
    expect(JSON.stringify(f)).not.toContain("person@example.com");
  });
});
