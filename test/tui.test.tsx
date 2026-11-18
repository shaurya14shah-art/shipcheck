import { execFileSync } from "node:child_process";
import { EventEmitter } from "node:events";
import { existsSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { render } from "ink";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { App, type Job } from "../src/tui/app.js";
import { FAKE, tempDir } from "./helpers.js";

/** A fake terminal with a real size, so layout and key handling run exactly as in a TTY. */
class Term extends EventEmitter {
  frames: string[] = [];
  isTTY = true;
  constructor(
    public columns: number,
    public rows: number,
  ) {
    super();
  }
  write = (s: string) => {
    this.frames.push(s);
    return true;
  };
  last = () => this.frames.at(-1) ?? "";
}
class Keys extends EventEmitter {
  isTTY = true;
  private data: string | null = null;
  setEncoding() {}
  setRawMode() {}
  resume() {}
  pause() {}
  ref() {}
  unref() {}
  read = () => {
    const d = this.data;
    this.data = null;
    return d;
  };
  press = (s: string) => {
    this.data = s;
    this.emit("readable");
    this.emit("data", s);
  };
}

const KEY = { down: "\u001B[B", up: "\u001B[A", enter: "\r", esc: "\u001B", tab: "\t" };
// eslint-disable-next-line no-control-regex
const plain = (s: string) => s.replace(/\u001B\[[0-9;?]*[A-Za-z]/g, "");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const FRAMES = process.env.SHIPCHECK_FRAMES;

let instances: Array<{ unmount: () => void }> = [];
function mount(columns: number, rows: number, initial?: Job) {
  const out = new Term(columns, rows);
  const keys = new Keys();
  const inst = render(<App initial={initial} />, {
    stdout: out as unknown as NodeJS.WriteStream,
    stdin: keys as unknown as NodeJS.ReadStream,
    stderr: new Term(columns, rows) as unknown as NodeJS.WriteStream,
    debug: true,
    exitOnCtrlC: false,
    patchConsole: false,
  });
  instances.push(inst);
  const frame = () => plain(out.last());
  const until = async (pred: (f: string) => boolean, ms = 8000) => {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      if (pred(frame())) return frame();
      await sleep(25);
    }
    throw new Error(`Timed out. Last frame:\n${frame()}`);
  };
  const press = async (k: string) => {
    keys.press(k);
    await sleep(60);
  };
  const snap = (name: string) => FRAMES && writeFileSync(join(FRAMES, `${name}.ansi`), JSON.stringify({ columns, rows, frame: out.last() }));
  return { frame, until, press, snap };
}

afterEach(() => {
  for (const i of instances) i.unmount();
  instances = [];
});
beforeEach(() => {
  process.env.SHIPCHECK_HOME = tempDir("shipcheck-tui-home-");
});

let repo: string;
beforeAll(() => {
  if (FRAMES) mkdirSync(FRAMES, { recursive: true });
  repo = tempDir("shipcheck-tui-repo-");
  const sh = (...a: string[]) => execFileSync("git", a, { cwd: repo, stdio: "ignore" });
  sh("init", "-q");
  sh("config", "user.email", "t@example.com");
  sh("config", "user.name", "t");
  mkdirSync(join(repo, "src"));
  mkdirSync(join(repo, "supabase"));
  writeFileSync(join(repo, "src/pay.ts"), `export const stripe = "${FAKE.stripeLive}";\n`);
  writeFileSync(join(repo, "src/db.ts"), `export const url = "${FAKE.dbUrl}";\n`);
  writeFileSync(join(repo, ".env.production"), `VITE_STRIPE_SECRET_KEY=${FAKE.stripeLive}\n`);
  writeFileSync(join(repo, "supabase/schema.sql"), "create table profiles (id uuid primary key, email text);\n");
  writeFileSync(join(repo, "vite.config.ts"), "export default { build: { sourcemap: true } }\n");
  sh("add", "-A");
  sh("commit", "-qm", "init");
});

const longestLine = (f: string) => Math.max(...f.split("\n").map((l) => [...l].length));

describe("visual app", () => {
  it("opens on a menu and moves between screens with the keyboard", async () => {
    const t = mount(110, 34);
    await t.until((f) => f.includes("Scan this folder"));
    expect(t.frame()).toMatch(/2,500 free files left this month/);
    t.snap("1-welcome");
    await t.press(KEY.down);
    await t.press(KEY.down);
    await t.press(KEY.enter);
    await t.until((f) => f.includes("Which website?"));
    t.snap("2-prompt");
    await t.press(KEY.esc);
    await t.until((f) => f.includes("Scan this folder"));
  });

  it("toggles git history from the menu", async () => {
    const t = mount(110, 34);
    await t.until((f) => f.includes("○ off"));
    await t.press("h");
    await t.until((f) => f.includes("● on"));
  });

  it("scans a repo and shows findings with a detail pane", async () => {
    const t = mount(120, 36, { kind: "repo", target: repo, history: false });
    const f = await t.until((x) => x.includes("critical") && x.includes("fix"));
    expect(f).toMatch(/Stripe live secret key/);
    expect(f).toMatch(/Table without row level security/);
    expect(f).toMatch(/Roll the key in the Stripe dashboard/);
    expect(f).not.toContain(FAKE.stripeLive);
    expect(longestLine(f)).toBeLessThanOrEqual(120);
    t.snap("3-results");
  });

  it("moves the selection, filters by severity and exports a report", async () => {
    const t = mount(120, 36, { kind: "repo", target: repo, history: false });
    await t.until((x) => x.includes("fix"));
    const before = t.frame().match(/▌● ([^\n]+)/)?.[1];
    await t.press(KEY.down);
    const after = t.frame().match(/▌● ([^\n]+)/)?.[1];
    expect(after).not.toEqual(before);
    await t.press(KEY.tab); // all -> critical
    await t.until((x) => /critical \d+ /.test(x) && !x.includes("Database URL with password"));
    t.snap("4-filtered");
    await t.press("e");
    await t.until((x) => x.includes("Saved"));
    const reports = join(process.env.SHIPCHECK_HOME as string, "reports");
    expect(existsSync(reports) && readdirSync(reports).some((n) => n.endsWith(".sarif"))).toBe(true);
  });

  it("stacks the panes and stays inside a narrow terminal", async () => {
    const t = mount(80, 40, { kind: "repo", target: repo, history: false });
    const f = await t.until((x) => x.includes("fix"));
    expect(longestLine(f)).toBeLessThanOrEqual(80);
    t.snap("5-narrow");
  });

  it("celebrates a clean repo", async () => {
    const clean = tempDir("shipcheck-clean-");
    writeFileSync(join(clean, "index.ts"), "export const ok = true;\n");
    const t = mount(110, 30, { kind: "repo", target: clean, history: false });
    await t.until((x) => x.includes("No problems found"));
    t.snap("6-clean");
  });
});
