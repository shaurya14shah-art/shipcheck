#!/usr/bin/env node
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { Meter, PRICING } from "./billing.js";
import { formatText, toSarif } from "./report.js";
import { scanRepo } from "./repo/scan.js";
import { SEVERITIES, severityRank, type ScanResult, type Severity } from "./types.js";
import { scanUrl } from "./url/scan.js";
import { checkOwnership, WELL_KNOWN } from "./url/verify.js";

const HELP = `shipcheck: find leaked keys, open databases and exposed source before attackers do

  shipcheck                  open the visual app (menus, live progress, results browser)
  shipcheck repo [path]      scan a git repo (current files)
      --history              also scan every past version of every file
  shipcheck url <url>        scan a live site: bundles, source maps, headers, cookies
      --active               also test exposed files and open databases (needs verify)
  shipcheck verify <url>     prove you own a site so --active is allowed
  shipcheck pricing          show prices

  --fail-on <level>          exit 1 at or above: critical | high | medium | low (default high)
  --json <file>              write findings as JSON
  --sarif <file>             write SARIF for GitHub code scanning
  --estimate                 show what a scan would cost, without reporting findings
  --verbose                  also list low-severity findings
`;

function die(msg: string, code = 2): never {
  process.stderr.write(`shipcheck: ${msg}\n`);
  process.exit(code);
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      history: { type: "boolean" },
      active: { type: "boolean" },
      "fail-on": { type: "string", default: "high" },
      json: { type: "string" },
      sarif: { type: "string" },
      estimate: { type: "boolean" },
      verbose: { type: "boolean", short: "v" },
      "max-assets": { type: "string" },
      help: { type: "boolean", short: "h" },
    },
  });
  const [cmd, arg] = positionals;
  if (values.help) return void process.stdout.write(HELP);
  if (!cmd || cmd === "app" || cmd === "ui") {
    // The visual app needs a real terminal; piped or CI output gets the help text instead.
    if (!process.stdout.isTTY || !process.stdin.isTTY) return void process.stdout.write(HELP);
    const { runTui } = await import("./tui/index.js");
    return runTui();
  }

  if (cmd === "pricing") {
    process.stdout.write(
      [
        "Billed per file checked, to the company account.",
        `  first ${PRICING.freeFilesPerMonth.toLocaleString()} files each month   free`,
        `  then                          $${(PRICING.perFile * 1000).toFixed(2)} per 1,000 files`,
        `  over ${PRICING.volumeThreshold.toLocaleString()} files a month   $${(PRICING.volumePerFile * 1000).toFixed(2)} per 1,000 files`,
        "Unchanged files are free to re-check: content you already paid for is never billed twice.",
        "A URL scan bills each page, script and source map it fetches.",
        "",
      ].join("\n"),
    );
    return;
  }

  if (cmd === "verify") {
    if (!arg) die("verify needs a URL");
    const origin = new URL(/^https?:\/\//.test(arg) ? arg : `https://${arg}`).origin;
    const r = await checkOwnership(origin, async (u) => {
      const res = await fetch(u, { signal: AbortSignal.timeout(10_000) });
      return { status: res.status, text: await res.text() };
    });
    if (r.ok) process.stdout.write(`Verified ${origin}. You can now run: shipcheck url ${origin} --active\n`);
    else {
      process.stdout.write(`Serve this exact text at ${origin}${WELL_KNOWN}, then run this command again:\n\n  ${r.token}\n`);
      process.exit(1);
    }
    return;
  }

  const failOn = values["fail-on"] as Severity;
  if (!SEVERITIES.includes(failOn)) die(`--fail-on must be one of ${SEVERITIES.join(", ")}`);
  const meter = new Meter();
  let result: ScanResult;

  if (cmd === "repo") {
    result = await scanRepo(resolve(arg ?? "."), meter, { history: values.history });
  } else if (cmd === "url") {
    if (!arg) die("url needs a URL");
    const maxAssets = values["max-assets"] ? Number(values["max-assets"]) : undefined;
    try {
      result = await scanUrl(arg, meter, { active: values.active, maxAssets });
    } catch (e) {
      die((e as Error).message);
    }
  } else die(`unknown command "${cmd}"\n\n${HELP}`);

  const bill = values.estimate ? meter.quote() : meter.commit();
  process.stdout.write(formatText(result, bill, { verbose: values.verbose, estimate: values.estimate }) + "\n");
  if (values.estimate) return;

  if (values.json) writeFileSync(values.json, JSON.stringify({ ...result, bill }, null, 2) + "\n");
  if (values.sarif) writeFileSync(values.sarif, JSON.stringify(toSarif(result), null, 2) + "\n");
  if (result.findings.some((f) => severityRank(f.severity) >= severityRank(failOn))) process.exit(1);
}

main().catch((e: unknown) => die((e as Error).stack ?? String(e)));
