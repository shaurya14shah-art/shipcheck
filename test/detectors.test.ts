import { describe, expect, it } from "vitest";
import { clientExposedSecrets, firebaseRules, sensitiveFile, sourcemapConfig, supabaseRls } from "../src/detectors/config.js";
import { entropy, findSecrets, mask, secretFindings } from "../src/detectors/secrets.js";
import { FAKE } from "./helpers.js";

const ids = (text: string) => findSecrets(text).map((h) => `${h.rule.id}:${h.severity}`);

describe("secret detection", () => {
  it("finds each provider's key with the right severity", () => {
    expect(ids(`const k = "${FAKE.stripeLive}"`)).toEqual(["stripe-live:critical"]);
    expect(ids(`STRIPE=${FAKE.stripeTest}`)).toEqual(["stripe-test:low"]);
    expect(ids(`aws_access_key_id = ${FAKE.aws}`)).toEqual(["aws-access-key:critical"]);
    expect(ids(`token: ${FAKE.github}`)).toEqual(["github-token:critical"]);
    expect(ids(`OPENAI_API_KEY=${FAKE.openai}`)).toEqual(["openai:critical"]);
    expect(ids(`ANTHROPIC_API_KEY=${FAKE.anthropic}`)).toEqual(["anthropic:critical"]);
    expect(ids(`key=${FAKE.sendgrid}`)).toEqual(["sendgrid:critical"]);
    expect(ids(`//registry.npmjs.org/:_authToken=${FAKE.npm}`)).toEqual(["npm-token:critical"]);
    expect(ids(FAKE.pem)).toEqual(["private-key:critical"]);
    expect(ids(`DATABASE_URL=${FAKE.dbUrl}`)).toEqual(["database-url:high"]);
  });

  it("flags the Supabase service_role key but never the public anon key", () => {
    expect(ids(`SUPABASE_SERVICE_ROLE_KEY=${FAKE.serviceRole}`)).toEqual(["supabase-service-role:critical"]);
    expect(ids(`createClient(url, "${FAKE.anon}")`)).toEqual([]);
  });

  it("skips placeholders, documentation keys and local dev databases", () => {
    expect(ids("AKIAIOSFODNN7EXAMPLE")).toEqual([]);
    expect(ids('api_key = "your-api-key-here-please"')).toEqual([]);
    expect(ids('password = "process.env.DB_PASSWORD"')).toEqual([]);
    expect(ids("postgres://postgres:postgres@localhost:5432/dev")).toEqual([]);
    expect(ids(`postgres://app:${"q".repeat(3)}Zx9!kLm2@localhost/dev`)).toEqual(["database-url:low"]);
  });

  it("catches generic hard-coded secrets by entropy, not by keyword alone", () => {
    expect(ids(`const apiKey = "${FAKE.generic}";`)).toEqual(["generic-secret:medium"]);
    expect(ids('const secretName = "billing-service-account";')).toEqual([]);
    expect(ids('password: "aaaaaaaaaaaaaaaa"')).toEqual([]);
  });

  it("needs key material after a private key header (not just a search string)", () => {
    expect(ids('let pattern = "-----BEGIN PRIVATE KEY-----"')).toEqual([]);
    const escaped = FAKE.pem.replace(/\n/g, "\\n");
    expect(ids(`const key = "${escaped}"`)).toEqual(["private-key:critical"]);
  });

  it("downgrades hits in test code to low", () => {
    const [f] = secretFindings(`k = "${FAKE.stripeLive}"`, "Tests/AppTests/RedactTests.swift");
    expect(f?.severity).toBe("low");
    expect(f?.title).toMatch(/in test code/);
    expect(secretFindings(`k = "${FAKE.stripeLive}"`, "src/__tests__/a.ts")[0]?.severity).toBe("low");
    expect(secretFindings(`k = "${FAKE.stripeLive}"`, "src/contest.ts")[0]?.severity).toBe("critical");
  });

  it("prefers the specific rule over the generic one for the same value", () => {
    expect(ids(`stripe_secret_key = "${FAKE.stripeLive}"`)).toEqual(["stripe-live:critical"]);
  });

  it("reports the right line and never the full secret", () => {
    const [f] = secretFindings(`a\nb\nconst k = "${FAKE.stripeLive}"\n`, "src/pay.ts");
    expect(f?.line).toBe(3);
    expect(f?.evidence).not.toContain(FAKE.stripeLive);
    expect(mask(FAKE.stripeLive)).toMatch(/^sk_live_\w{2}…\w{2} \(36 chars\)$/);
    expect(mask("abcdefghij")).toBe("abcd…ij (10 chars)");
  });

  it("entropy separates random keys from words", () => {
    expect(entropy(FAKE.generic)).toBeGreaterThan(4);
    expect(entropy("passwordpassword")).toBeLessThan(3);
  });
});

describe("config checks", () => {
  it("flags committed env files and keys but not templates", () => {
    expect(sensitiveFile(".env")?.severity).toBe("high");
    expect(sensitiveFile("apps/web/.env.production")?.severity).toBe("high");
    expect(sensitiveFile(".env.example")).toBeNull();
    expect(sensitiveFile("deploy/id_ed25519")?.severity).toBe("critical");
    expect(sensitiveFile("deploy/id_ed25519.pub")).toBeNull();
    expect(sensitiveFile("infra/terraform.tfstate")?.severity).toBe("high");
    expect(sensitiveFile("src/index.ts")).toBeNull();
  });

  it("flags secrets with browser-exposed prefixes", () => {
    const f = clientExposedSecrets("NEXT_PUBLIC_SUPABASE_URL=x\nNEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=y\n# VITE_OLD_SECRET=z\n", ".env.local");
    expect(f.map((x) => x.evidence)).toEqual(["NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY"]);
    expect(clientExposedSecrets("const k = import.meta.env.VITE_STRIPE_SECRET_KEY", "src/a.ts")).toHaveLength(1);
    expect(clientExposedSecrets("const k = import.meta.env.VITE_STRIPE_PUBLISHABLE_KEY", "src/a.ts")).toHaveLength(0);
  });

  it("flags open and test-mode Firebase rules", () => {
    expect(firebaseRules("match /{d=**} { allow read, write: if true; }", "firestore.rules")[0]?.severity).toBe("critical");
    expect(firebaseRules("allow read, write: if request.time < timestamp.date(2027, 1, 1);", "firestore.rules")[0]?.check).toBe("config/firebase-test-mode");
    expect(firebaseRules("allow read: if request.auth != null;", "firestore.rules")).toEqual([]);
    expect(firebaseRules('{"rules": {".read": true, ".write": false}}', "database.rules.json")).toHaveLength(1);
  });

  it("flags production source maps", () => {
    expect(sourcemapConfig("export default { build: { sourcemap: true } }", "vite.config.ts")).toHaveLength(1);
    expect(sourcemapConfig("export default { build: { sourcemap: 'hidden' } }", "vite.config.ts")).toHaveLength(0);
    expect(sourcemapConfig("module.exports = { productionBrowserSourceMaps: true }", "next.config.js")).toHaveLength(1);
  });

  it("finds Supabase tables without RLS across migrations", () => {
    const files = [
      { path: "supabase/migrations/1_init.sql", text: 'create table public.profiles (id uuid);\ncreate table "Orders" (id int);\ncreate table private.audit (id int);\n-- create table ghost (id int);' },
      { path: "supabase/migrations/2_rls.sql", text: "alter table profiles enable row level security;\ncreate policy \"open\" on profiles for insert to anon with check (true);" },
    ];
    const f = supabaseRls(files);
    expect(f.filter((x) => x.check === "supabase/rls-disabled").map((x) => x.evidence)).toEqual(["public.orders"]);
    const policy = f.find((x) => x.check === "supabase/open-write-policy");
    expect(policy?.evidence).toMatch(/open/);
    expect(policy?.severity).toBe("medium");
    const all = supabaseRls([{ path: "supabase/m.sql", text: 'create table t (id int);\nalter table t enable row level security;\ncreate policy "w" on t for all to anon using (true);' }]);
    expect(all[0]?.severity).toBe("high");
  });

  it("does not flag read-only public policies", () => {
    const f = supabaseRls([{ path: "supabase/m.sql", text: 'create table posts (id int);\nalter table posts enable row level security;\ncreate policy "read" on posts for select using (true);' }]);
    expect(f).toEqual([]);
  });
});
