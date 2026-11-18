import { existsSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { resolve } from "node:path";
import { Box, Text, useAnimation, useApp, useInput, useWindowSize } from "ink";
import TextInput from "ink-text-input";
import { useEffect, useState } from "react";
import { Meter, PRICING, type Bill } from "../billing.js";
import { scanRepo } from "../repo/scan.js";
import { SEVERITIES, type ScanResult } from "../types.js";
import { scanUrl } from "../url/scan.js";
import { ago, loadRecent, saveRecent } from "./recent.js";
import { Results } from "./results.js";
import { ACCENT, ACCENT_2, DIM, FAINT, LOGO, LOGO_GRADIENT, SEV_COLOR, tilde, truncate } from "./theme.js";

export interface Job {
  kind: "repo" | "url";
  target: string;
  history: boolean;
  active?: boolean;
}

type Screen =
  | { name: "welcome" }
  | { name: "prompt"; kind: "repo" | "url" }
  | { name: "scanning"; job: Job }
  | { name: "results"; job: Job; result: ScanResult; bill: Bill }
  | { name: "pricing" }
  | { name: "error"; message: string; job?: Job };

/** One-line key bar. Hints are in priority order; trailing ones are dropped when the terminal is narrow. */
export function KeyHints({ hints }: { hints: Array<[string, string]> }) {
  const { columns } = useWindowSize();
  const shown: Array<[string, string]> = [];
  let used = 2;
  for (const h of hints) {
    const w = h[0].length + h[1].length + 1 + (shown.length ? 3 : 0);
    if (used + w > columns - 1) break;
    shown.push(h);
    used += w;
  }
  return (
    <Box paddingX={1}>
      <Text wrap="truncate-end">
        {shown.map(([key, label], i) => (
          <Text key={key}>
            {i > 0 && <Text color={FAINT}> · </Text>}
            <Text color={ACCENT} bold>
              {key}
            </Text>
            <Text color={DIM}> {label}</Text>
          </Text>
        ))}
      </Text>
    </Box>
  );
}

function Logo({ compact }: { compact: boolean }) {
  if (compact) {
    return (
      <Text bold color={ACCENT}>
        ◆ shipcheck
      </Text>
    );
  }
  return (
    <Box flexDirection="column">
      {LOGO.map((line, i) => (
        <Text key={i} color={LOGO_GRADIENT[i]}>
          {line}
        </Text>
      ))}
    </Box>
  );
}

interface MenuItem {
  key: string;
  label: string;
  detail?: string;
  detailColor?: string;
  run: () => void;
}

function Welcome({ go, history, setHistory }: { go: (s: Screen) => void; history: boolean; setHistory: (v: boolean) => void }) {
  const { exit } = useApp();
  const { columns, rows } = useWindowSize();
  const [sel, setSel] = useState(0);
  const recent = loadRecent().slice(0, 3);
  const freeLeft = new Meter().freeLeft;
  const cwd = process.cwd();

  const items: MenuItem[] = [
    { key: "here", label: "Scan this folder", detail: tilde(cwd), run: () => go({ name: "scanning", job: { kind: "repo", target: cwd, history } }) },
    { key: "repo", label: "Scan a repo…", detail: "any folder on this machine", run: () => go({ name: "prompt", kind: "repo" }) },
    { key: "url", label: "Scan a website…", detail: "keys in your JS, source maps, headers", run: () => go({ name: "prompt", kind: "url" }) },
    ...recent.map((r) => {
      const worst = SEVERITIES.find((s) => (r.counts[s] ?? 0) > 0);
      return {
        key: `recent-${r.target}`,
        label: `↻ ${truncate(r.kind === "repo" ? tilde(r.target) : r.target, 34)}`,
        detail: worst ? `${r.counts[worst]} ${worst} · ${ago(r.at)}` : `clean · ${ago(r.at)}`,
        detailColor: worst ? SEV_COLOR[worst] : ACCENT,
        run: () => go({ name: "scanning", job: { kind: r.kind, target: r.target, history } }),
      };
    }),
    { key: "history", label: `Include git history  ${history ? "● on" : "○ off"}`, detail: "finds keys you deleted but never rotated", run: () => setHistory(!history) },
    { key: "pricing", label: "Pricing", run: () => go({ name: "pricing" }) },
    { key: "quit", label: "Quit", run: () => exit() },
  ];

  useInput((input, key) => {
    if (key.upArrow || input === "k") setSel((s) => (s - 1 + items.length) % items.length);
    else if (key.downArrow || input === "j") setSel((s) => (s + 1) % items.length);
    else if (key.return) items[sel]?.run();
    else if (input === "h") setHistory(!history);
    else if (input === "q" || key.escape) exit();
  });

  const width = Math.min(72, columns - 4);
  return (
    <Box flexDirection="column" width={columns} height={rows}>
      <Box flexGrow={1} alignItems="center" justifyContent="center">
        <Box flexDirection="column" borderStyle="round" borderColor={ACCENT} paddingX={3} paddingY={1} width={width}>
          <Logo compact={width < 62 || rows < 24} />
          <Box marginTop={1} marginBottom={1}>
            <Text color={DIM}>Find leaked keys, open databases and exposed source before attackers do.</Text>
          </Box>
          {items.map((it, i) => {
            const active = i === sel;
            const isRecentStart = it.key.startsWith("recent-") && !items[i - 1]?.key.startsWith("recent-");
            return (
              <Box key={it.key} flexDirection="column">
                {(isRecentStart || it.key === "history") && <Text color={FAINT}>{"─".repeat(width - 8)}</Text>}
                <Text wrap="truncate-end">
                  <Text color={active ? ACCENT : FAINT}>{active ? "▸ " : "  "}</Text>
                  <Text bold={active} color={active ? "white" : undefined}>
                    {it.label}
                  </Text>
                  {it.detail && <Text color={it.detailColor ?? DIM}>{`  ${truncate(it.detail, Math.max(0, width - it.label.length - 14))}`}</Text>}
                </Text>
              </Box>
            );
          })}
          {/* One inline paragraph: side-by-side <Text> siblings get flex-shrunk and clipped. */}
          <Box marginTop={1}>
            <Text>
              <Text color={freeLeft > 0 ? ACCENT : SEV_COLOR.medium}>{freeLeft.toLocaleString()}</Text>
              <Text color={DIM}> free files left this month · nothing is uploaded</Text>
            </Text>
          </Box>
        </Box>
      </Box>
      <KeyHints hints={[["↑↓", "move"], ["enter", "select"], ["h", "history"], ["q", "quit"]]} />
    </Box>
  );
}

function Prompt({ kind, go, history }: { kind: "repo" | "url"; go: (s: Screen) => void; history: boolean }) {
  const { columns, rows } = useWindowSize();
  const [value, setValue] = useState(kind === "repo" ? tilde(process.cwd()) + "/" : "");
  const [error, setError] = useState("");

  useInput((_input, key) => {
    if (key.escape) go({ name: "welcome" });
  });

  const submit = (raw: string) => {
    const v = raw.trim();
    if (!v) return setError("Type something first.");
    if (kind === "repo") {
      const full = resolve(v.replace(/^~(?=$|\/)/, homedir()));
      if (!existsSync(full) || !statSync(full).isDirectory()) return setError(`No folder at ${full}`);
      go({ name: "scanning", job: { kind, target: full, history } });
    } else {
      try {
        const u = new URL(/^https?:\/\//i.test(v) ? v : `https://${v}`);
        go({ name: "scanning", job: { kind, target: u.toString(), history: false } });
      } catch {
        setError("That is not a valid URL.");
      }
    }
  };

  return (
    <Box flexDirection="column" width={columns} height={rows}>
      <Box flexGrow={1} alignItems="center" justifyContent="center">
        <Box flexDirection="column" borderStyle="round" borderColor={ACCENT} paddingX={3} paddingY={1} width={Math.min(76, columns - 4)}>
          <Text bold color={ACCENT}>
            {kind === "repo" ? "Which folder?" : "Which website?"}
          </Text>
          <Text color={DIM}>
            {kind === "repo" ? "A git repo or any project folder. Nothing is uploaded." : "Your own site. Checks the page, its scripts and source maps."}
          </Text>
          <Box marginTop={1} borderStyle="single" borderColor={error ? SEV_COLOR.critical : FAINT} paddingX={1}>
            <Text color={ACCENT}>{"› "}</Text>
            <TextInput
              value={value}
              onChange={(v) => {
                setValue(v);
                setError("");
              }}
              onSubmit={submit}
              placeholder={kind === "repo" ? "~/projects/my-app" : "myapp.com"}
            />
          </Box>
          {error ? <Text color={SEV_COLOR.critical}>{error}</Text> : <Text> </Text>}
        </Box>
      </Box>
      <KeyHints hints={[["enter", "scan"], ["esc", "back"]]} />
    </Box>
  );
}

const SPIN = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

function Scanning({ job, go }: { job: Job; go: (s: Screen) => void }) {
  const { exit } = useApp();
  const { columns, rows } = useWindowSize();
  const { frame, time } = useAnimation({ interval: 80 });
  const [p, setP] = useState({ phase: "Starting", done: 0, total: 0, findings: 0 });

  useEffect(() => {
    let cancelled = false;
    const meter = new Meter();
    const run = job.kind === "repo" ? scanRepo(job.target, meter, { history: job.history, onProgress: setP }) : scanUrl(job.target, meter, { active: job.active, onProgress: setP });
    run.then(
      (result) => {
        if (cancelled) return;
        const bill = meter.commit();
        const counts = Object.fromEntries(SEVERITIES.map((s) => [s, result.findings.filter((f) => f.severity === s).length]));
        saveRecent({ kind: job.kind, target: job.kind === "repo" ? job.target : result.target, history: job.history, at: Date.now(), counts });
        go({ name: "results", job, result, bill });
      },
      (e: unknown) => !cancelled && go({ name: "error", message: (e as Error).message, job }),
    );
    return () => {
      cancelled = true;
    };
  }, [job]);

  useInput((input) => {
    if (input === "q") exit();
  });

  const barWidth = Math.min(48, columns - 16);
  const ratio = p.total > 0 ? Math.min(1, p.done / p.total) : 0;
  const filled = Math.round(ratio * barWidth);
  // Indeterminate phases get a sweeping highlight instead of a fake percentage.
  const sweep = Math.floor(time / 40) % (barWidth + 8);
  const bar =
    p.total > 0
      ? "█".repeat(filled) + "░".repeat(barWidth - filled)
      : Array.from({ length: barWidth }, (_, i) => (Math.abs(i - sweep + 4) < 4 ? "█" : "░")).join("");

  return (
    <Box flexDirection="column" width={columns} height={rows}>
      <Box flexGrow={1} alignItems="center" justifyContent="center" flexDirection="column">
        <Text color={DIM}>{job.kind === "repo" ? "scanning repo" : "scanning website"}</Text>
        <Text bold>{truncate(job.kind === "repo" ? tilde(job.target) : job.target, columns - 6)}</Text>
        <Box marginTop={1}>
          <Text>
            <Text color={ACCENT}>{SPIN[frame % SPIN.length]} </Text>
            <Text>{p.phase}</Text>
            {p.total > 0 && <Text color={DIM}>{`  ${p.done.toLocaleString()} / ${p.total.toLocaleString()}`}</Text>}
          </Text>
        </Box>
        <Box marginTop={1}>
          <Text color={ACCENT}>{bar}</Text>
        </Box>
        <Box marginTop={1}>
          <Text>
            <Text color={p.findings ? SEV_COLOR.high : DIM}>{p.findings ? `${p.findings} problem${p.findings === 1 ? "" : "s"} so far` : "no problems so far"}</Text>
            <Text color={FAINT}>{`  ·  ${(time / 1000).toFixed(1)}s`}</Text>
          </Text>
        </Box>
      </Box>
      <KeyHints hints={[["q", "quit"]]} />
    </Box>
  );
}

function Pricing({ go }: { go: (s: Screen) => void }) {
  const { columns, rows } = useWindowSize();
  const freeLeft = new Meter().freeLeft;
  useInput((_i, key) => {
    if (key.escape || key.return || _i === "b") go({ name: "welcome" });
  });
  const row = (a: string, b: string, color = "white") => (
    <Box>
      <Box width={30}>
        <Text color={DIM}>{a}</Text>
      </Box>
      <Text bold color={color}>
        {b}
      </Text>
    </Box>
  );
  const per1k = (n: number) => `$${(n * 1000).toFixed(2)} per 1,000 files`;
  return (
    <Box flexDirection="column" width={columns} height={rows}>
      <Box flexGrow={1} alignItems="center" justifyContent="center">
        <Box flexDirection="column" borderStyle="round" borderColor={ACCENT} paddingX={3} paddingY={1} width={Math.min(70, columns - 4)}>
          <Text bold color={ACCENT}>
            Pay per file checked
          </Text>
          <Text color={DIM}>Billed to the company. Unchanged files are always free to re-check.</Text>
          <Box flexDirection="column" marginTop={1}>
            {row(`First ${PRICING.freeFilesPerMonth.toLocaleString()} files / month`, "free", ACCENT)}
            {row("Then", per1k(PRICING.perFile))}
            {row(`Past ${PRICING.volumeThreshold.toLocaleString()} / month`, per1k(PRICING.volumePerFile))}
          </Box>
          <Box flexDirection="column" marginTop={1}>
            <Text color={ACCENT_2}>Typical costs</Text>
            {row("Side project, 300 files", "free")}
            {row("Startup repo, 4,000 files", "$3.00 first scan")}
            {row("CI on every push (~40 changed)", "≈ $0.08 per push")}
            {row("Website scan", "≈ 10–60 files")}
          </Box>
          <Box marginTop={1}>
            <Text>
              <Text color={DIM}>You have </Text>
              <Text color={ACCENT}>{freeLeft.toLocaleString()}</Text>
              <Text color={DIM}> free files left this month.</Text>
            </Text>
          </Box>
        </Box>
      </Box>
      <KeyHints hints={[["esc", "back"]]} />
    </Box>
  );
}

function ErrorScreen({ message, job, go }: { message: string; job?: Job; go: (s: Screen) => void }) {
  const { columns, rows } = useWindowSize();
  const { exit } = useApp();
  useInput((input, key) => {
    if (key.escape || key.return || input === "b") go({ name: "welcome" });
    else if (input === "r" && job) go({ name: "scanning", job });
    else if (input === "q") exit();
  });
  return (
    <Box flexDirection="column" width={columns} height={rows}>
      <Box flexGrow={1} alignItems="center" justifyContent="center">
        <Box flexDirection="column" borderStyle="round" borderColor={SEV_COLOR.critical} paddingX={3} paddingY={1} width={Math.min(80, columns - 4)}>
          <Text bold color={SEV_COLOR.critical}>
            Scan did not finish
          </Text>
          <Box marginTop={1}>
            <Text>{message}</Text>
          </Box>
        </Box>
      </Box>
      <KeyHints hints={[...(job ? ([["r", "retry"]] as Array<[string, string]>) : []), ["esc", "back"], ["q", "quit"]]} />
    </Box>
  );
}

export function App({ initial }: { initial?: Job }) {
  const [screen, setScreen] = useState<Screen>(initial ? { name: "scanning", job: initial } : { name: "welcome" });
  const [history, setHistory] = useState(initial?.history ?? false);

  switch (screen.name) {
    case "welcome":
      return <Welcome go={setScreen} history={history} setHistory={setHistory} />;
    case "prompt":
      return <Prompt kind={screen.kind} go={setScreen} history={history} />;
    case "scanning":
      return <Scanning job={screen.job} go={setScreen} />;
    case "pricing":
      return <Pricing go={setScreen} />;
    case "error":
      return <ErrorScreen message={screen.message} job={screen.job} go={setScreen} />;
    case "results":
      return (
        <Results
          job={screen.job}
          result={screen.result}
          bill={screen.bill}
          onBack={() => setScreen({ name: "welcome" })}
          onRescan={(job) => setScreen({ name: "scanning", job })}
        />
      );
  }
}
