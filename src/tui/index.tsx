import { render } from "ink";
import { App, type Job } from "./app.js";

/** Full-screen visual mode. Runs in the terminal's alternate screen, like vim or htop. */
export async function runTui(initial?: Job): Promise<void> {
  const app = render(<App initial={initial} />, { alternateScreen: true, exitOnCtrlC: true });
  await app.waitUntilExit();
}
