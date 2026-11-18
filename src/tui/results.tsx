import { execFile, spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { Box, Text, useApp, useInput, useWindowSize } from "ink";
import { useEffect, useMemo, useState } from "react";
import type { Bill } from "../billing.js";
import { sortFindings, toSarif } from "../report.js";
import { SEVERITIES, type Finding, type ScanResult, type Severity } from "../types.js";
import type { Job } from "./app.js";
import { KeyHints } from "./app.js";
import { ACCENT, DIM, FAINT, SEV_COLOR, SEV_LABEL, tilde, truncate, truncateLeft } from "./theme.js";

type Filter = "all" | Severity;
const FILTERS: Filter[] = ["all", ...SEVERITIES];

interface Props {
  job: Job;
  result: ScanResult;
  bill: Bill;
  onBack: () => void;
  onRescan: (job: Job) => void;
}

const where = (f: Finding) => `${f.location}${f.line ? `:${f.line}` : ""}`;

function SeverityBar({ findings, width }: { findings: Finding[]; width: number }) {
  const total = findings.length || 1;
  // Largest-remainder split so the segments add up to exactly `width` (plain rounding can overflow and wrap).
  const counts = SEVERITIES.map((s) => findings.filter((f) => f.severity === s).length);
  const exact = counts.map((n) => (n / total) * width);
  const widths = exact.map((x, i) => ((counts[i] as number) > 0 ? Math.max(1, Math.floor(x)) : 0));
  let spare = width - widths.reduce((a, b) => a + b, 0);
  const order = exact.map((x, i) => [x - Math.floor(x), i] as const).sort((a, b) => b[0] - a[0]);
  for (const [, i] of order) {
    if (spare <= 0) break;
    if ((counts[i] as number) > 0) {
      widths[i] = (widths[i] as number) + 1;
      spare--;
    }
  }
  while (spare < 0) {
    const i = widths.indexOf(Math.max(...widths));
    widths[i] = (widths[i] as number) - 1;
    spare++;
  }
  return (
    <Text>
      {SEVERITIES.map((s, i) => {
        const w = widths[i] as number;
        return (
          <Text key={s} color={SEV_COLOR[s]}>
            {"▀".repeat(w)}
          </Text>
        );
      })}
    </Text>
  );
}

function Detail({ f, width, root }: { f: Finding; width: number; root: string }) {
  return (
    <Box flexDirection="column" width={width}>
      <Box>
        <Text backgroundColor={SEV_COLOR[f.severity]} color="#111111" bold>
          {` ${SEV_LABEL[f.severity]} `}
        </Text>
        {f.historyOnly && (
          <Text backgroundColor="#7c5cd6" color="white" bold>
            {" GIT HISTORY "}
          </Text>
        )}
      </Box>
      <Box marginTop={1}>
        <Text bold>{f.title}</Text>
      </Box>
      <Text color={ACCENT}>{truncateLeft(where(f), width)}</Text>
      {f.evidence && (
        <Box marginTop={1} flexDirection="column">
          <Text color={DIM}>found</Text>
          <Text>{f.evidence}</Text>
        </Box>
      )}
      <Box marginTop={1} flexDirection="column">
        <Text color={DIM}>fix</Text>
        <Text wrap="wrap">{f.fix}</Text>
      </Box>
      <Box marginTop={1}>
        <Text color={FAINT} wrap="truncate-start">
          {`${f.check}${root ? `  ·  ${truncateLeft(tilde(root), Math.max(8, width - f.check.length - 5))}` : ""}`}
        </Text>
      </Box>
    </Box>
  );
}

export function Results({ job, result, bill, onBack, onRescan }: Props) {
  const { exit } = useApp();
  const { columns, rows } = useWindowSize();
  const [filter, setFilter] = useState<Filter>("all");
  const [showLows, setShowLows] = useState(false);
  const [sel, setSel] = useState(0);
  const [toast, setToast] = useState("");

  const all = useMemo(() => sortFindings(result.findings), [result]);
  const lows = all.filter((f) => f.severity === "low").length;
  const list = all.filter((f) => (filter === "all" ? showLows || f.severity !== "low" : f.severity === filter));
  const current = list[Math.min(sel, list.length - 1)];

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(""), 3000);
    return () => clearTimeout(t);
  }, [toast]);
  useEffect(() => setSel(0), [filter, showLows]);

  const openTarget = (f: Finding) => {
    const target = result.kind === "repo" && !/^https?:/.test(f.location) ? join(result.target, f.location) : f.location;
    execFile("open", [target], (err) => setToast(err ? `Could not open ${basename(target)}` : `Opened ${basename(target)}`));
  };
  const copy = (text: string, what: string) => {
    const p = spawn("pbcopy");
    p.on("error", () => setToast("Clipboard not available"));
    p.on("close", (code) => code === 0 && setToast(`Copied ${what}`));
    p.stdin.end(text);
  };
  const exportReport = () => {
    const dir = join(process.env.SHIPCHECK_HOME ?? join(homedir(), ".shipcheck"), "reports");
    const name = `${basename(result.target).replace(/[^a-z0-9.-]+/gi, "_") || "scan"}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}`;
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, `${name}.json`), JSON.stringify({ ...result, bill }, null, 2));
    writeFileSync(join(dir, `${name}.sarif`), JSON.stringify(toSarif(result), null, 2));
    setToast(`Saved ${tilde(join(dir, name))}.json + .sarif`);
  };

  useInput((input, key) => {
    if (key.upArrow || input === "k") setSel((s) => Math.max(0, s - 1));
    else if (key.downArrow || input === "j") setSel((s) => Math.min(list.length - 1, s + 1));
    else if (key.pageDown) setSel((s) => Math.min(list.length - 1, s + 10));
    else if (key.pageUp) setSel((s) => Math.max(0, s - 10));
    else if (key.tab || input === "f") setFilter((f) => FILTERS[(FILTERS.indexOf(f) + (key.shift ? FILTERS.length - 1 : 1)) % FILTERS.length] as Filter);
    else if (input === "l") setShowLows((v) => !v);
    else if ((key.return || input === "o") && current) openTarget(current);
    else if (input === "c" && current) copy(`${where(current)}\n${current.title}\nFix: ${current.fix}`, "finding and fix");
    else if (input === "e") exportReport();
    else if (input === "r") onRescan({ ...job });
    else if (input === "h" && job.kind === "repo") onRescan({ ...job, history: !job.history });
    else if (input === "a" && job.kind === "url") onRescan({ ...job, active: true });
    else if (input === "b" || key.escape) onBack();
    else if (input === "q") exit();
  });

  const wide = columns >= 100;
  const listWidth = wide ? Math.floor(columns * 0.55) : columns - 2;
  const detailWidth = wide ? columns - listWidth - 5 : columns - 4;
  // Rows: header 4, filter row 2, key hints 1, toast 1; stacked layout gives the detail ~11 rows.
  const bodyRows = Math.max(3, rows - 9 - (wide ? 0 : 12));
  const offset = Math.min(Math.max(0, sel - Math.floor(bodyRows / 2)), Math.max(0, list.length - bodyRows));
  const visible = list.slice(offset, offset + bodyRows);
  const counts = SEVERITIES.map((s) => [s, all.filter((f) => f.severity === s).length] as const);
  const worst = counts.find(([, n]) => n > 0)?.[0];
  const cost = bill.usd > 0 ? `$${bill.usd.toFixed(2)}` : "free";

  const listPane = (
    <Box flexDirection="column" width={listWidth}>
      {visible.map((f, i) => {
        const idx = offset + i;
        const active = idx === Math.min(sel, list.length - 1);
        // The title matters more than the path: cap the path at ~38% of the row and shorten it from the left.
        const loc = truncateLeft(`${where(f)}${f.historyOnly ? " ⟲" : ""}`, Math.max(10, Math.floor(listWidth * 0.38)));
        const titleWidth = Math.max(8, listWidth - loc.length - 5);
        return (
          <Text key={`${f.check}-${f.location}-${f.line}-${idx}`} wrap="truncate-end">
            <Text color={active ? ACCENT : FAINT}>{active ? "▌" : " "}</Text>
            <Text color={SEV_COLOR[f.severity]}>● </Text>
            <Text bold={active} color={active ? "white" : undefined}>
              {truncate(f.title, titleWidth).padEnd(titleWidth)}
            </Text>
            <Text color={active ? DIM : FAINT}> {loc}</Text>
          </Text>
        );
      })}
      {list.length > bodyRows && <Text color={FAINT}>{`  ${offset + 1}–${Math.min(list.length, offset + bodyRows)} of ${list.length}`}</Text>}
    </Box>
  );

  return (
    <Box flexDirection="column" width={columns} height={rows}>
      {/* Header */}
      <Box paddingX={1} justifyContent="space-between">
        <Text>
          <Text bold color={ACCENT}>
            ◆ shipcheck
          </Text>
          <Text color={DIM}>{`  ${job.kind}${job.history ? " + history" : ""}${job.active ? " + active" : ""}  `}</Text>
          <Text bold>{truncate(job.kind === "repo" ? tilde(result.target) : result.target, columns - 60)}</Text>
        </Text>
        <Text color={DIM}>
          {`${result.filesChecked.toLocaleString()} files · ${bill.billableFiles.toLocaleString()} new · `}
          <Text color={bill.usd > 0 ? SEV_COLOR.medium : ACCENT}>{cost}</Text>
        </Text>
      </Box>
      <Box paddingX={1}>
        {worst ? (
          <Text>
            {counts
              .filter(([, n]) => n > 0)
              .map(([s, n], i) => (
                <Text key={s}>
                  {i > 0 && "   "}
                  <Text color={SEV_COLOR[s]} bold>
                    {n}
                  </Text>
                  <Text color={DIM}>{` ${s}`}</Text>
                </Text>
              ))}
          </Text>
        ) : (
          <Text color={ACCENT} bold>
            ✓ Nothing to fix
          </Text>
        )}
      </Box>
      <Box paddingX={1}>{all.length > 0 ? <SeverityBar findings={all} width={columns - 2} /> : <Text color={ACCENT}>{"▀".repeat(columns - 2)}</Text>}</Box>

      {/* Filters */}
      <Box paddingX={1} marginTop={1}>
        {FILTERS.map((f) => {
          const n = f === "all" ? all.length : all.filter((x) => x.severity === f).length;
          const on = filter === f;
          return (
            <Text key={f}>
              <Text backgroundColor={on ? ACCENT : undefined} color={on ? "#0b1410" : f === "all" ? undefined : SEV_COLOR[f]} bold={on}>
                {` ${f} ${n} `}
              </Text>
              <Text> </Text>
            </Text>
          );
        })}
        {filter === "all" && lows > 0 && <Text color={FAINT}>{showLows ? "  lows shown" : `  ${lows} low hidden`}</Text>}
      </Box>

      {/* Body */}
      <Box flexGrow={1} flexDirection={wide ? "row" : "column"} paddingX={1} marginTop={1}>
        {list.length === 0 ? (
          <Box flexGrow={1} alignItems="center" justifyContent="center" flexDirection="column">
            <Text color={ACCENT} bold>
              {all.length === 0 ? "✓ No problems found" : "Nothing at this level"}
            </Text>
            <Text color={DIM}>
              {all.length === 0
                ? job.kind === "repo" && !job.history
                  ? "Press h to also check git history for deleted keys."
                  : "Ship it."
                : "Press tab to change the filter, l to show lows."}
            </Text>
          </Box>
        ) : (
          <>
            {listPane}
            {wide ? (
              <Box borderStyle="single" borderLeft borderTop={false} borderRight={false} borderBottom={false} borderColor={FAINT} paddingLeft={2} marginLeft={1}>
                {current && <Detail f={current} width={detailWidth} root={result.kind === "repo" ? result.target : ""} />}
              </Box>
            ) : (
              <Box borderStyle="single" borderTop borderLeft={false} borderRight={false} borderBottom={false} borderColor={FAINT} marginTop={1}>
                {current && <Detail f={current} width={detailWidth} root="" />}
              </Box>
            )}
          </>
        )}
      </Box>

      {/* Notes and toast */}
      <Box paddingX={1}>
        <Text color={toast ? ACCENT : FAINT} wrap="truncate-end">
          {toast || result.notes[0] || " "}
        </Text>
      </Box>
      <KeyHints
        // Priority order: quitting and navigating must always stay visible.
        hints={[
          ["↑↓", "select"],
          ["q", "quit"],
          ["b", "back"],
          ["enter", "open"],
          ["c", "copy fix"],
          ["tab", "filter"],
          job.kind === "repo" ? ["h", job.history ? "no history" : "+history"] : ["a", "active"],
          ["e", "export"],
          ["r", "rescan"],
          ["l", "lows"],
        ]}
      />
    </Box>
  );
}
