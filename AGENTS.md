# AGENTS.md: shipcheck

Security CLI: scans git repos and live URLs. No AI. Per-file billing.

## Rules
- Never print a full secret. Use `mask()`. Never print database rows or Firebase keys, only counts.
- Active URL checks (file probes, Supabase/Firebase reads) only after ownership verification (`/.well-known/shipcheck.txt`), except local dev hosts.
- Fake secrets in tests are built at runtime in `test/helpers.ts`. Never write a realistic key literal into the repo.
- Every new detector needs a test proving it catches the real thing AND skips the obvious false positive. Re-run on real repos (`~/AG/*`) and check every finding by hand before shipping.
- Output stays terse: one line per finding plus the fix. Lows hidden unless `--verbose`. The user dislikes wordy output.

## Gate
```
npx tsc --noEmit && npx vitest run && npm run build
```
Use a throwaway `SHIPCHECK_HOME` when scanning real repos so the meter is not polluted. macOS has no `timeout` command.

## Visual app (src/tui, Ink 8 + React)
`shipcheck` with no args opens it (alternate screen). Installed globally with `npm link` (bin in ~/.local/bin); rebuild with `npm run build` after changes or the global command runs stale code.
Never put several `<Text>` siblings in a row `<Box>`: Ink flex-shrinks them and clips text ("2,500" became "2,50"). Nest them inside one `<Text>`.
Verify visually: `FORCE_COLOR=3 SHIPCHECK_FRAMES=<dir> npx vitest run test/tui.test.tsx` captures ANSI frames; render them to a PNG contact sheet with puppeteer. Test at 120 and 80 columns.

## Layout
`src/detectors/` secrets + config checks · `src/repo/scan.ts` · `src/url/scan.ts`, `verify.ts` · `src/billing.ts` (pricing + meter) · `src/report.ts` (text, SARIF) · `src/cli.ts`
