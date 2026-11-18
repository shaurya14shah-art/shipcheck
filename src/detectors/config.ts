import type { Finding } from "../types.js";

const base = (p: string) => p.split("/").pop() ?? p;

const ENV_TEMPLATE = /^\.env\.(example|sample|template|dist|defaults)$/i;

/** Files that should never be committed, judged by name alone. */
export function sensitiveFile(path: string): Finding | null {
  const name = base(path);
  const f = (severity: Finding["severity"], title: string, fix: string): Finding => ({ check: `file/${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`, severity, title, fix, location: path });

  if ((name === ".env" || /^\.env\./i.test(name)) && !ENV_TEMPLATE.test(name)) {
    return f("high", "Environment file committed", "Delete it from git (`git rm --cached`), add it to .gitignore, and rotate every value in it.");
  }
  if (/^id_(rsa|dsa|ecdsa|ed25519)$/.test(name)) return f("critical", "SSH private key committed", "Replace this SSH key everywhere it is authorised and purge it from history.");
  if (/\.(p12|pfx|keystore|jks)$/i.test(name)) return f("high", "Certificate keystore committed", "Keystores hold private keys. Remove it and reissue the certificate.");
  if (/^terraform\.tfstate(\.backup)?$/.test(name)) return f("high", "Terraform state committed", "State files contain secrets in plain text. Move state to a remote backend and rotate secrets.");
  if (/\.(sqlite3?|db)$/i.test(name) && !/test|fixture|seed/i.test(path)) return f("medium", "Database file committed", "Check it for user data. If it holds any, remove it and purge history.");
  if (/^(\.htpasswd|\.pgpass|\.netrc|\.git-credentials)$/.test(name)) return f("high", "Credentials file committed", "Remove it, rotate the credentials, and add it to .gitignore.");
  return null;
}

const PUBLIC_PREFIX = "(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|PUBLIC_|GATSBY_)";
const SECRET_WORD = "(?:SECRET|SERVICE_ROLE|SERVICE_KEY|PRIVATE|PASSWORD|ADMIN_KEY)";
const CLIENT_SECRET_VAR = new RegExp(`\\b(${PUBLIC_PREFIX}[A-Z0-9_]*${SECRET_WORD}[A-Z0-9_]*)\\b`, "g");

/** Env vars with a browser-exposed prefix but a secret-looking name: they end up in the JS bundle. */
export function clientExposedSecrets(text: string, path: string): Finding[] {
  const out = new Map<string, Finding>();
  const lines = text.split("\n");
  lines.forEach((line, i) => {
    if (/^\s*(#|\/\/)/.test(line)) return;
    for (const m of line.matchAll(CLIENT_SECRET_VAR)) {
      const name = m[1] as string;
      if (out.has(name)) continue;
      out.set(name, {
        check: "config/client-exposed-secret",
        severity: "high",
        title: "Secret exposed to the browser",
        fix: `Variables starting with ${/^[A-Z]+_PUBLIC_|^[A-Z]+_/.exec(name)?.[0] ?? "this prefix"} are bundled into client JavaScript that anyone can read. Rename it without the public prefix and use it only on the server.`,
        location: path,
        line: i + 1,
        evidence: name,
      });
    }
  });
  return [...out.values()];
}

/** Firebase security rules that let anyone read or write. */
export function firebaseRules(text: string, path: string): Finding[] {
  const name = base(path);
  const out: Finding[] = [];
  const lineOf = (re: RegExp) => {
    const i = text.split("\n").findIndex((l) => re.test(l));
    return i < 0 ? undefined : i + 1;
  };
  if (/\.rules$/.test(name)) {
    const open = /allow\s+(?:read|write|read\s*,\s*write|write\s*,\s*read|get|list|create|update|delete)[^;]*:\s*if\s+true\s*;|allow\s+(?:read\s*,\s*)?write\s*;/;
    if (open.test(text)) {
      out.push({
        check: "config/firebase-open-rules",
        severity: "critical",
        title: "Firebase rules allow anyone",
        fix: "Replace `if true` with a check such as `request.auth != null && request.auth.uid == userId`.",
        location: path,
        line: lineOf(open),
      });
    } else if (/request\.time\s*<\s*timestamp\.date\(/.test(text)) {
      out.push({
        check: "config/firebase-test-mode",
        severity: "high",
        title: "Firebase still in test mode",
        fix: "Test-mode rules let anyone read and write until the date. Write real rules before launch.",
        location: path,
        line: lineOf(/request\.time\s*</),
      });
    }
  }
  if (name === "database.rules.json") {
    try {
      const rules = (JSON.parse(text) as { rules?: Record<string, unknown> }).rules ?? {};
      if (rules[".read"] === true || rules[".write"] === true) {
        out.push({
          check: "config/firebase-open-rules",
          severity: "critical",
          title: "Realtime Database open to anyone",
          fix: 'Set ".read" and ".write" to auth-based conditions instead of true.',
          location: path,
        });
      }
    } catch {
      /* not JSON; ignore */
    }
  }
  return out;
}

/** Build configs that publish source maps to production. */
export function sourcemapConfig(text: string, path: string): Finding[] {
  const name = base(path);
  const hit = (title: string): Finding[] => [
    {
      check: "config/production-sourcemaps",
      severity: "medium",
      title,
      fix: "Source maps let anyone read your original source. Use `sourcemap: 'hidden'` or upload them privately to your error tracker.",
      location: path,
      line: text.split("\n").findIndex((l) => /sourcemap|SourceMaps/i.test(l)) + 1 || undefined,
    },
  ];
  if (/^next\.config\.(js|mjs|cjs|ts)$/.test(name) && /productionBrowserSourceMaps\s*:\s*true/.test(text)) return hit("Next.js ships source maps");
  if (/^vite\.config\.(js|mjs|cjs|ts|mts)$/.test(name) && /sourcemap\s*:\s*(true|['"]inline['"])/.test(text)) return hit("Vite build ships source maps");
  return [];
}

const ident = String.raw`(?:"[^"]+"|[A-Za-z_][A-Za-z0-9_]*)`;
const qualified = new RegExp(String.raw`(?:(${ident})\s*\.\s*)?(${ident})`);
const unquote = (s: string) => s.replace(/"/g, "").toLowerCase();

function tableKey(raw: string): string | null {
  const m = qualified.exec(raw.trim());
  if (!m) return null;
  const schema = m[1] ? unquote(m[1]) : "public";
  return `${schema}.${unquote(m[2] as string)}`;
}

/**
 * Supabase: every table in the public schema needs row level security, or the anon key
 * (which ships in your frontend) can read and write it. Checks all migrations together.
 */
export function supabaseRls(files: Array<{ path: string; text: string }>): Finding[] {
  const created = new Map<string, { path: string; line: number }>();
  const protectedTables = new Set<string>();
  const openPolicies: Finding[] = [];
  const strip = (sql: string) => sql.replace(/--[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "");

  for (const f of files) {
    const sql = strip(f.text);
    const lineAt = (idx: number) => sql.slice(0, idx).split("\n").length;
    for (const m of sql.matchAll(/create\s+table\s+(?:if\s+not\s+exists\s+)?([^\s(]+(?:\s*\.\s*[^\s(]+)?)\s*\(/gi)) {
      const key = tableKey(m[1] as string);
      if (key && key.startsWith("public.") && !created.has(key)) created.set(key, { path: f.path, line: lineAt(m.index ?? 0) });
    }
    for (const m of sql.matchAll(/alter\s+table\s+(?:only\s+)?(?:if\s+exists\s+)?([^\s]+(?:\s*\.\s*[^\s]+)?)\s+enable\s+row\s+level\s+security/gi)) {
      const key = tableKey(m[1] as string);
      if (key) protectedTables.add(key);
    }
    for (const m of sql.matchAll(/create\s+policy\s+("[^"]*"|\S+)\s+on\s+([^\s]+)([\s\S]*?);/gi)) {
      const body = m[3] as string;
      const forAnyone = /\bto\s+(?:anon|public)\b/i.test(body) || !/\bto\s+/i.test(body);
      const writes = /\bfor\s+(?:all|insert|update|delete)\b/i.test(body) || !/\bfor\s+/i.test(body);
      if (forAnyone && writes && /(?:using|with\s+check)\s*\(\s*true\s*\)/i.test(body)) {
        // Insert-only lets strangers add rows (spam, fake scores); update/delete/all lets them change or wipe yours.
        const insertOnly = /\bfor\s+insert\b/i.test(body);
        openPolicies.push({
          check: "supabase/open-write-policy",
          severity: insertOnly ? "medium" : "high",
          title: insertOnly ? "Policy lets anyone insert rows" : "Policy lets anyone change data",
          fix: insertOnly
            ? "Anyone with your anon key can add rows without logging in. Require auth (`to authenticated`) or validate in an edge function."
            : "Anyone can update or delete rows. Restrict it, for example `using (auth.uid() = user_id)`.",
          location: f.path,
          line: lineAt(m.index ?? 0),
          evidence: `${m[1]} on ${m[2]}`,
        });
      }
    }
  }

  const missing: Finding[] = [...created]
    .filter(([key]) => !protectedTables.has(key))
    .map(([key, at]) => ({
      check: "supabase/rls-disabled",
      severity: "critical",
      title: "Table without row level security",
      fix: `Anyone with your public anon key can read and change ${key}. Add \`alter table ${key} enable row level security;\` and write policies.`,
      location: at.path,
      line: at.line,
      evidence: key,
    }));
  return [...missing, ...openPolicies];
}
