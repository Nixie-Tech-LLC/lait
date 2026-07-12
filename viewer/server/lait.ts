import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

// viewer/server/lait.ts -> repo root is two levels up.
const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..");

// Resolve the lait binary. Prefer an explicit override, then a build in this
// repo's target/, then fall back to `lait` on PATH. When we have a concrete
// path we spawn without a shell so titles/bodies with spaces pass through as
// literal argv entries (no shell escaping); only the bare-PATH fallback needs a
// shell to be found on Windows.
function resolveBin(): { cmd: string; shell: boolean } {
  const override = process.env.LAIT_BIN;
  if (override && existsSync(override)) return { cmd: override, shell: false };

  const candidates = [
    path.join(repoRoot, "target", "release", "lait.exe"),
    path.join(repoRoot, "target", "debug", "lait.exe"),
    path.join(repoRoot, "target", "release", "lait"),
    path.join(repoRoot, "target", "debug", "lait"),
  ];
  for (const c of candidates) if (existsSync(c)) return { cmd: c, shell: false };

  return { cmd: "lait", shell: true };
}

const bin = resolveBin();

export class LaitError extends Error {
  code: number;
  constructor(message: string, code = 500) {
    super(message);
    this.code = code;
  }
}

/**
 * Run `lait <args>` and return the parsed `--json` DTO.
 *
 * lait emits exactly one line of JSON on --json (the versioned `Response`,
 * internally tagged by `kind`). We parse the last non-empty stdout line, surface
 * `{"kind":"error"}` as a 400, and any spawn/parse failure as a 500. Note the
 * first invocation auto-spawns lait's background daemon (single-writer over the
 * Loro store); that's expected and cached for subsequent calls.
 */
export function runLait(args: string[]): Promise<any> {
  const full = ["--json", ...args];
  return new Promise((resolve, reject) => {
    execFile(
      bin.cmd,
      full,
      {
        shell: bin.shell,
        cwd: repoRoot,
        timeout: 20_000,
        maxBuffer: 16 * 1024 * 1024,
        windowsHide: true,
      },
      (err, stdout, stderr) => {
        const out = String(stdout || "").trim();
        let parsed: any = null;
        if (out) {
          const line = out.split(/\r?\n/).filter(Boolean).pop();
          if (line) {
            try {
              parsed = JSON.parse(line);
            } catch {
              /* not JSON — fall through to error handling */
            }
          }
        }

        if (parsed && parsed.kind === "error") {
          return reject(new LaitError(String(parsed.message || "lait error"), 400));
        }
        if (!parsed) {
          const msg =
            String(stderr || "").trim() ||
            (err ? err.message : "lait produced no JSON output");
          return reject(new LaitError(msg, err ? 500 : 502));
        }
        resolve(parsed);
      },
    );
  });
}

/**
 * Run `lait <args>` and return raw stdout lines (no JSON parsing).
 *
 * A few commands (notably `invite`) print human text even under `--json`, so we
 * can't route them through `runLait`. This runs without forcing `--json` and
 * returns the non-empty stdout lines.
 */
export function runLaitRaw(args: string[]): Promise<string[]> {
  return new Promise((resolve, reject) => {
    execFile(
      bin.cmd,
      args,
      {
        shell: bin.shell,
        cwd: repoRoot,
        timeout: 20_000,
        maxBuffer: 4 * 1024 * 1024,
        windowsHide: true,
      },
      (err, stdout, stderr) => {
        const lines = String(stdout || "")
          .split(/\r?\n/)
          .map((l) => l.trim())
          .filter(Boolean);
        if (!lines.length) {
          return reject(
            new LaitError(String(stderr || "").trim() || (err ? err.message : "no output"), 500),
          );
        }
        resolve(lines);
      },
    );
  });
}

export function laitBinInfo() {
  return { cmd: bin.cmd, viaShell: bin.shell, repoRoot };
}
