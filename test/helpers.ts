import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Fake credentials are assembled at runtime so the repository never contains strings that
// look like real keys (which would also trip GitHub push protection).
const rand = (n: number, alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789") => {
  let s = "";
  let seed = 7;
  for (let i = 0; i < n; i++) {
    seed = (seed * 1103515245 + 12345) % 2147483648;
    s += alphabet[seed % alphabet.length];
  }
  return s;
};
const b64url = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");

export const FAKE = {
  stripeLive: ["sk", "live", rand(28)].join("_"),
  stripeTest: ["sk", "test", rand(28)].join("_"),
  aws: "AKIA" + rand(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
  github: "ghp" + "_" + rand(36),
  openai: "sk-" + "proj-" + rand(60),
  anthropic: "sk-" + "ant-api03-" + rand(90),
  sendgrid: "SG." + rand(22) + "." + rand(43),
  npm: "npm" + "_" + rand(36),
  serviceRole: `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "service_role" })}.${rand(43)}`,
  anon: `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({ iss: "supabase", ref: "abcdefghijklmnopqrst", role: "anon" })}.${rand(43)}`,
  pem: ["-----BEGIN", "RSA PRIVATE KEY-----"].join(" ") + "\nMIIEow" + rand(60) + "\n-----END RSA PRIVATE KEY-----",
  dbUrl: `postgres://app_user:${rand(20)}@db.prod-cluster.example-host.io:5432/app`,
  generic: rand(32),
};

export const tempDir = (prefix: string) => mkdtempSync(join(tmpdir(), prefix));
