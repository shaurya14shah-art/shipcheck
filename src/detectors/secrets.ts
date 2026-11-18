import type { Finding, Severity } from "../types.js";

interface SecretRule {
  id: string;
  name: string;
  severity: Severity;
  re: RegExp;
  /** Capture group holding the secret itself (default: whole match). */
  group?: number;
  /** Extra check on the captured value; return a severity override, or null to drop the match. */
  judge?: (value: string, line: string) => Severity | null;
  fix: string;
}

const PLACEHOLDER = /example|sample|dummy|placeholder|changeme|change_me|your[_-]?|xxxx|\*\*\*|<[^>]*>|\$\{|\{\{|process\.env|import\.meta|os\.environ|getenv/i;

/** Shannon entropy in bits per character. Random keys sit well above 3.5; words and paths below. */
export function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Decode a JWT payload without verifying it. Returns null when it is not a JWT. */
export function jwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const json = Buffer.from((parts[1] as string).replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    const obj = JSON.parse(json) as unknown;
    return obj && typeof obj === "object" ? (obj as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

const ROTATE = "Revoke and rotate this key now, then load it from an environment variable or secret manager.";

export const SECRET_RULES: SecretRule[] = [
  { id: "aws-access-key", name: "AWS access key", severity: "critical", re: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/g, group: 1, fix: ROTATE },
  {
    id: "aws-secret-key",
    name: "AWS secret access key",
    severity: "critical",
    re: /aws.{0,24}(?:secret|private).{0,24}?['"=:\s]\s*['"]?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])/gi,
    group: 1,
    judge: (v) => (entropy(v) > 4 ? "critical" : null),
    fix: ROTATE,
  },
  {
    id: "stripe-live",
    name: "Stripe live secret key",
    severity: "critical",
    re: /\b((?:sk|rk)_live_[0-9a-zA-Z]{20,})\b/g,
    group: 1,
    fix: "Roll the key in the Stripe dashboard now. Anyone holding it can move money on your account.",
  },
  { id: "stripe-test", name: "Stripe test secret key", severity: "low", re: /\b(sk_test_[0-9a-zA-Z]{20,})\b/g, group: 1, fix: "Test keys cannot move money, but keep them out of code anyway." },
  {
    id: "openai",
    name: "OpenAI API key",
    severity: "critical",
    re: /\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})\b/g,
    group: 1,
    fix: ROTATE,
  },
  { id: "anthropic", name: "Anthropic API key", severity: "critical", re: /\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,})/g, group: 1, fix: ROTATE },
  { id: "github-token", name: "GitHub token", severity: "critical", re: /\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b/g, group: 1, fix: ROTATE },
  { id: "slack-token", name: "Slack token", severity: "high", re: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g, group: 1, fix: ROTATE },
  {
    id: "slack-webhook",
    name: "Slack webhook URL",
    severity: "medium",
    re: /(https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]{20,})/g,
    group: 1,
    fix: "Anyone can post into your Slack with this. Regenerate the webhook.",
  },
  { id: "sendgrid", name: "SendGrid API key", severity: "critical", re: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g, group: 1, fix: ROTATE },
  { id: "npm-token", name: "npm access token", severity: "critical", re: /\b(npm_[A-Za-z0-9]{36})\b/g, group: 1, fix: "Revoke it on npmjs.com. Someone could publish malware as you." },
  {
    id: "private-key",
    name: "Private key",
    severity: "critical",
    // The header alone is often just a search string in code; require key material after it
    // (real newlines or escaped `\n` inside a string literal).
    re: /(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)(?:\s|\\n|\\r)+[A-Za-z0-9+/=]{40,}/g,
    group: 1,
    fix: "Treat the key as compromised: replace it and remove the file from the repo and its history.",
  },
  {
    id: "supabase-service-role",
    name: "Supabase service_role key",
    severity: "critical",
    re: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})/g,
    group: 1,
    // Only the service_role JWT is secret. Anon keys are public by design and are skipped.
    judge: (v) => (jwtPayload(v)?.role === "service_role" ? "critical" : null),
    fix: "This key bypasses all row level security. Rotate the JWT secret in Supabase and keep this key server-side only.",
  },
  {
    id: "supabase-secret",
    name: "Supabase secret key",
    severity: "critical",
    re: /\b(sb_secret_[A-Za-z0-9_-]{20,})/g,
    group: 1,
    fix: "This key bypasses row level security. Revoke it in Supabase and keep secret keys server-side only.",
  },
  {
    id: "google-api-key",
    name: "Google API key",
    severity: "low",
    re: /\b(AIza[0-9A-Za-z_-]{35})\b/g,
    group: 1,
    fix: "Fine for a Firebase web config, but restrict it to your domains and APIs in Google Cloud console.",
  },
  {
    id: "database-url",
    name: "Database URL with password",
    severity: "high",
    re: /\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp):\/\/[^:\s'"/@]+:([^@\s'"]{4,})@([^\s'"/:]+)[^\s'"]*)/g,
    group: 1,
    judge: (v) => {
      const m = /:\/\/[^:]+:([^@]+)@([^/:?]+)/.exec(v);
      if (!m) return null;
      const [, pw = "", host = ""] = m;
      if (PLACEHOLDER.test(pw) || /^(password|pass|postgres|root|admin|secret)$/i.test(pw)) return null;
      if (/^(localhost|127\.0\.0\.1|0\.0\.0\.0|db|postgres|mysql|redis|mongo)$/i.test(host)) return "low";
      return "high";
    },
    fix: "Change the database password and move the connection string into an environment variable.",
  },
  {
    id: "generic-secret",
    name: "Hard-coded secret",
    severity: "medium",
    re: /\b([A-Za-z0-9_]*(?:secret|password|passwd|api_?key|apikey|access_?token|auth_?token|private_?key)[A-Za-z0-9_]*)\s*[:=]\s*['"]([^'"\s]{12,})['"]/gi,
    group: 2,
    judge: (v, line) => {
      if (PLACEHOLDER.test(v) || PLACEHOLDER.test(line)) return null;
      if (/^[a-z]+(?:[._-][a-z]+)*$/i.test(v)) return null; // words and identifiers, not secrets
      if (/^(?:https?:|\/|\.)/.test(v)) return null; // URLs and paths
      return entropy(v) >= 3.6 ? "medium" : null;
    },
    fix: "Move this value into an environment variable or secret manager, and rotate it if it is real.",
  },
];

/** Show enough to recognise the key, never enough to use it. */
export function mask(secret: string): string {
  if (secret.startsWith("-----BEGIN")) return secret;
  // Keep a recognisable provider prefix (sk_live_, ghp_, sk-proj-) but never more than 40% of the value.
  const prefix = /^[A-Za-z0-9]{1,6}(?:[_-][A-Za-z0-9]{1,6}){0,2}[_-]/.exec(secret.slice(0, 14))?.[0].length ?? 0;
  const keep = Math.min(Math.max(prefix + 2, 4), Math.floor(secret.length * 0.4));
  return `${secret.slice(0, keep)}…${secret.slice(-2)} (${secret.length} chars)`;
}

export interface TextHit {
  rule: SecretRule;
  value: string;
  severity: Severity;
  line: number;
}

/** Find secrets in text. One hit per distinct value, strongest rule wins. */
export function findSecrets(text: string): TextHit[] {
  const hits = new Map<string, TextHit>();
  const lineStarts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) lineStarts.push(i + 1);
  const lineOf = (idx: number) => {
    let lo = 0;
    let hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if ((lineStarts[mid] as number) <= idx) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
  const lineText = (n: number) => text.slice(lineStarts[n - 1], (lineStarts[n] ?? text.length + 1) - 1);

  for (const rule of SECRET_RULES) {
    rule.re.lastIndex = 0;
    for (const m of text.matchAll(rule.re)) {
      const value = m[rule.group ?? 0] ?? m[0];
      if (!value || /EXAMPLE|XXXXXXXX/.test(value)) continue;
      const line = lineOf(m.index ?? 0);
      const sev = rule.judge ? rule.judge(value, lineText(line)) : rule.severity;
      if (!sev) continue;
      const prev = hits.get(value);
      if (prev && prev.rule.id !== "generic-secret") continue;
      hits.set(value, { rule, value, severity: sev, line });
    }
  }
  return [...hits.values()];
}

/** Test code is full of fake keys; a hit there is worth a look, not an alarm. */
export const TEST_PATH = /(^|\/)(tests?|__tests__|spec|specs|fixtures?|__fixtures__|testdata|mocks?|__mocks__)\/|[._-](test|spec)\.[a-z]+$|_test\.(go|py|rb)$|Tests?\.swift$/i;

export function secretFindings(text: string, location: string): Finding[] {
  const inTests = TEST_PATH.test(location);
  return findSecrets(text).map((h) => ({
    check: `secret/${h.rule.id}`,
    severity: inTests ? "low" : h.severity,
    title: inTests ? `${h.rule.name} (in test code)` : h.rule.name,
    fix: inTests ? `Probably a fake fixture. If it is real: ${h.rule.fix}` : h.rule.fix,
    location,
    line: h.line,
    evidence: mask(h.value),
  }));
}
