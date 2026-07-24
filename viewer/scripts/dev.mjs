#!/usr/bin/env node
/**
 * `npm run dev` — the whole loop, one command.
 *
 * It used to be three steps and a copy-paste: run `lait serve`, find the token in
 * the URL it prints, then `LAIT_TOKEN=<that> npm run dev` in a second terminal. Every
 * one of those steps is mechanical, which is exactly the kind of thing that should
 * not be a person's job — and the only place it was written down was a comment inside
 * `vite.config.ts`, so nobody found it anyway.
 *
 * So: spawn the engine, read the token off its `--json` line, hand it to vite.
 *
 * **Why a token at all.** Vite serves the client on :5178 and the engine listens on
 * :7717 — two origins, which `serve::auth` refuses by design. The dev *proxy* adapts
 * rather than the engine relaxing its guard, because a guard with a dev exemption is
 * not a guard (see the note in `vite.config.ts`). The proxy therefore has to present
 * a credential the browser's cookie jar cannot supply, and that is the run's token.
 *
 * **No new dependencies.** This is `child_process` and `readline` — a dev-loop helper
 * that needs `npm install` to fix an npm-install-shaped problem is not a fix.
 */

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { createRequire } from "node:module";
import { accessSync, constants } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..");
const IS_WINDOWS = process.platform === "win32";
const EXE = IS_WINDOWS ? "lait.exe" : "lait";

/** The engine's own default (`serve::DEFAULT_PORT`), which the proxy also assumes. */
const DEFAULT_PORT = "7717";

/**
 * Find the binary to drive.
 *
 * Debug before release, deliberately: you are editing this repo, so the build you
 * just made is the one you mean. `LAIT_BIN` overrides for anyone pointing at an
 * installed lait, and PATH is the last resort — it is the only candidate that might
 * be a *different version* than this checkout, so it is also the one we name out loud
 * when we use it.
 */
function findLait() {
  if (process.env.LAIT_BIN) return process.env.LAIT_BIN;
  for (const profile of ["debug", "release"]) {
    const candidate = join(REPO, "target", profile, EXE);
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch {
      // Not built in this profile — try the next.
    }
  }
  console.error(
    `[dev] no lait binary in ${join(REPO, "target")}/{debug,release} — falling back to PATH.\n` +
      `[dev] run \`cargo build\` first, or set LAIT_BIN, if you meant this checkout's engine.`,
  );
  return EXE;
}

/** Start the engine and resolve once it tells us where it is. */
function startEngine(bin, port) {
  return new Promise((ok, fail) => {
    const selector = process.env.LAIT_SPACE
      ? ["-w", process.env.LAIT_SPACE]
      : [];
    const child = spawn(bin, [...selector, "serve", "--port", port, "--json"], {
      cwd: REPO,
      stdio: ["ignore", "pipe", "inherit"],
    });

    child.on("error", (e) =>
      fail(new Error(`could not run ${bin}: ${e.message}`)),
    );
    // The common failure by a mile: a `lait serve` you forgot is still running, so
    // the bind fails. The engine already says so on stderr (which we inherit); this
    // just makes sure we don't hang waiting for a line that will never come.
    child.on("exit", (code) =>
      fail(new Error(`lait serve exited (${code}) before it was ready`)),
    );

    const lines = createInterface({ input: child.stdout });
    lines.on("line", (line) => {
      let info;
      try {
        info = JSON.parse(line);
      } catch {
        // Not our line. `--json` puts the object first, but a stray warning ahead
        // of it should be passed through rather than mistaken for a protocol error.
        console.error(line);
        return;
      }
      if (info?.kind === "error") {
        fail(new Error(info.message || "lait serve failed to start"));
        return;
      }
      if (!info?.token || typeof info.port !== "number") {
        fail(new Error("lait serve returned an invalid readiness reply"));
        return;
      }
      lines.close();
      child.removeAllListeners("exit");
      ok({ child, info });
    });
  });
}

/**
 * Start vite by running its JS entry with *this* node.
 *
 * Not `spawn("npm", ["exec", "vite"])` and not `spawn("vite")`: on Windows those
 * resolve to `.cmd` shims, and Node ≥20 refuses to spawn a `.cmd` without
 * `shell: true` (the CVE-2024-27980 argument-injection fix) — it throws a bare
 * `spawn EINVAL` that says nothing about why. Reaching for `shell: true` to get past
 * it trades one Windows quoting bug for another.
 *
 * Resolving the module and handing it to `process.execPath` sidesteps the shims
 * entirely, uses the same node that is already running, and honours npm's hoisting
 * wherever it put vite.
 *
 * Extra args pass through, so `npm run dev -- --host` still reaches vite.
 */
function startVite(env) {
  const require = createRequire(import.meta.url);
  // `require.resolve("vite/bin/vite.js")` fails: vite's `package.json` `exports`
  // does not list the bin subpath, and `exports`, once present, is a closed door.
  // `package.json` itself is always resolvable, so resolve that and read `bin` —
  // which is where the bin path is declared anyway, so we follow the truth rather
  // than a guess.
  const pkgPath = require.resolve("vite/package.json");
  const bin = require("vite/package.json").bin;
  const rel = typeof bin === "string" ? bin : bin.vite;
  const viteBin = join(dirname(pkgPath), rel);
  return spawn(process.execPath, [viteBin, ...process.argv.slice(2)], {
    cwd: resolve(HERE, ".."),
    stdio: "inherit",
    env,
  });
}

async function main() {
  const port = process.env.LAIT_PORT ?? DEFAULT_PORT;

  /**
   * An already-set `LAIT_TOKEN` means you are driving your own engine — a daemon
   * under a debugger, a space on a odd port, `lait serve` in another terminal you
   * want to keep. Spawning a second one over the top of that would be this script
   * deciding it knows better. Use what you were given and start vite.
   */
  if (process.env.LAIT_TOKEN) {
    console.error(`[dev] LAIT_TOKEN is set — using your engine on :${port}, not spawning one.`);
    const vite = startVite({ ...process.env, LAIT_PORT: port });
    vite.on("exit", (code) => process.exit(code ?? 0));
    return;
  }

  const bin = findLait();
  const { child: engine, info } = await startEngine(bin, port);

  // The port comes back from the engine rather than being echoed from our own
  // argument: `--port 0` is legal and binds an ephemeral one, and the proxy needs
  // the port that was actually bound.
  const actual = String(info.port ?? port);
  console.error(`[dev] engine on :${actual} — vite will proxy /api to it`);

  const vite = startVite({
    ...process.env,
    LAIT_TOKEN: info.token,
    LAIT_PORT: actual,
  });

  // The engine is ours; it should not outlive the loop it exists to serve. The
  // *daemons* it supervises are a separate matter and deliberately survive — they
  // are per-space and long-lived, and killing them here would make `npm run dev`
  // quietly stop whatever else was talking to them.
  let stopped = false;
  const stop = (code) => {
    if (stopped) return;
    stopped = true;
    engine.kill();
    process.exit(code ?? 0);
  };
  vite.on("exit", (code) => stop(code ?? 0));
  engine.on("exit", () => {
    console.error("[dev] engine exited — stopping vite");
    vite.kill();
    stop(1);
  });
  // Ctrl-C reaches the whole process group, so the children get it too; this is
  // belt-and-braces for the cases where it does not (Windows, notably).
  for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => stop(0));
}

main().catch((e) => {
  console.error(`[dev] ${e.message}`);
  process.exit(1);
});
