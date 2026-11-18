import { PRICING, type Bill } from "./billing.js";
import { SEVERITIES, severityRank, type Finding, type ScanResult, type Severity } from "./types.js";

const tty = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: string) => (s: string) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const C = { red: paint("1;31"), orange: paint("33"), yellow: paint("2;33"), dim: paint("2"), bold: paint("1"), green: paint("32") };
const sevColor: Record<Severity, (s: string) => string> = { critical: C.red, high: C.orange, medium: C.yellow, low: C.dim };

export const sortFindings = (fs: Finding[]) => [...fs].sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.location.localeCompare(b.location));

const money = (n: number) => `$${n.toFixed(2)}`;

export function billLine(bill: Bill, estimate: boolean): string {
  const freeLeft = Math.max(0, PRICING.freeFilesPerMonth - bill.usedThisMonthAfter);
  const cost = bill.usd > 0 ? money(bill.usd) : "free";
  return `${bill.billableFiles.toLocaleString()} new file${bill.billableFiles === 1 ? "" : "s"} · ${cost}${estimate ? " (estimate)" : ""} · ${freeLeft.toLocaleString()} free left this month`;
}

/** Short, scannable output: one line per problem plus the fix. Lows are counted, not listed, unless verbose. */
export function formatText(result: ScanResult, bill: Bill, opts: { verbose?: boolean; estimate?: boolean } = {}): string {
  const out: string[] = [];
  out.push(`${C.bold("shipcheck")} ${C.dim(result.kind)} ${result.target}`);
  if (opts.estimate) {
    out.push("", `${result.filesChecked.toLocaleString()} files to check`, billLine(bill, true));
    return out.join("\n");
  }

  const shown = sortFindings(result.findings).filter((f) => opts.verbose || f.severity !== "low");
  out.push("");
  if (shown.length === 0 && result.findings.length === 0) out.push(C.green("No problems found."));
  for (const f of shown) {
    const where = `${f.location}${f.line ? `:${f.line}` : ""}${f.historyOnly ? " (git history)" : ""}`;
    out.push(`${sevColor[f.severity](f.severity.toUpperCase().padEnd(8))}  ${C.bold(f.title)}  ${C.dim(where)}${f.evidence ? `  ${f.evidence}` : ""}`);
    out.push(`          ${C.dim("→")} ${f.fix}`);
  }

  const counts = SEVERITIES.map((s) => [s, result.findings.filter((f) => f.severity === s).length] as const).filter(([, n]) => n > 0);
  const hiddenLows = opts.verbose ? 0 : result.findings.filter((f) => f.severity === "low").length;
  out.push("");
  out.push(
    [
      counts.length ? counts.map(([s, n]) => sevColor[s](`${n} ${s}`)).join(" · ") : C.green("clean"),
      hiddenLows ? C.dim(`(lows hidden, --verbose)`) : "",
    ]
      .filter(Boolean)
      .join(" "),
  );
  out.push(C.dim(`${result.filesChecked.toLocaleString()} files checked · ${billLine(bill, false)}`));
  for (const n of result.notes) out.push(C.dim(n));
  return out.join("\n");
}

const sarifLevel: Record<Severity, string> = { critical: "error", high: "error", medium: "warning", low: "note" };

/** SARIF 2.1.0, for GitHub code scanning and other CI dashboards. */
export function toSarif(result: ScanResult): object {
  const rules = new Map<string, Finding>();
  for (const f of result.findings) if (!rules.has(f.check)) rules.set(f.check, f);
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "shipcheck",
            version: "0.1.0",
            rules: [...rules.values()].map((f) => ({
              id: f.check,
              name: f.title,
              shortDescription: { text: f.title },
              help: { text: f.fix },
              properties: { "security-severity": { critical: "9.5", high: "8.0", medium: "5.5", low: "2.0" }[f.severity] },
            })),
          },
        },
        results: result.findings.map((f) => ({
          ruleId: f.check,
          level: sarifLevel[f.severity],
          message: { text: `${f.title}${f.evidence ? ` (${f.evidence})` : ""}. ${f.fix}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.location },
                ...(f.line ? { region: { startLine: f.line } } : {}),
              },
            },
          ],
        })),
      },
    ],
  };
}
