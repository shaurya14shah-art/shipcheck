# shipcheck

Find leaked keys, open databases and exposed source code before attackers do.

```bash
shipcheck                     # visual app: menus, live progress, results browser
shipcheck repo .              # current files
shipcheck repo . --history    # plus every past version of every file
shipcheck url myapp.com       # live site: JS bundles, source maps, headers, cookies
shipcheck verify myapp.com    # prove ownership, then:
shipcheck url myapp.com --active   # downloadable .env/.git, readable Supabase tables, open Firebase
```

CI: `shipcheck repo . --fail-on high --sarif shipcheck.sarif` (exit 1 on findings; SARIF for GitHub code scanning).

## Checks
| Area | What |
|---|---|
| Secrets | Stripe, AWS, OpenAI, Anthropic, GitHub, Slack, SendGrid, npm, Supabase service_role, private keys, DB URLs, high-entropy hard-coded secrets. Public-by-design keys (Supabase anon, Firebase web) are not flagged. |
| Git | committed `.env`, SSH keys, keystores, tfstate; `.env` not ignored; secrets deleted from code but alive in history |
| Frontend leaks | `NEXT_PUBLIC_*SECRET`, `VITE_*SERVICE_ROLE` and similar (bundled to the browser); production source maps |
| Supabase | tables without row level security, policies letting anyone write; live: tables anyone can read (row counts only, never data) |
| Firebase | `if true` rules, test-mode rules; live: readable Realtime Database |
| Web | CSP, HSTS, framing, nosniff, version disclosure, cookie flags, HTTP→HTTPS |

Secrets are always masked. Code never leaves your machine.

## Pricing
Billed per file to the company. `shipcheck pricing`:
- 2,500 files a month free
- $2.00 per 1,000 files, $1.00 per 1,000 past 1M a month
- Unchanged files are free to re-check (deduped by SHA-256), so CI only pays for what changed.

Metering is local for now (`~/.shipcheck/meter.json`, hashes only). The hosted meter, accounts and payment are not built yet.
