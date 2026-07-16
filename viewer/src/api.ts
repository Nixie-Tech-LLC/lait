/**
 * The engine, from the browser.
 *
 * This file is the whole backend. The previous viewer had a `server/` directory —
 * a Vite middleware that spawned `lait --json` once per request and re-parsed its
 * stdout — because there was no other way in. `lait serve` exposes the control
 * plane directly, so all of that collapses to `fetch`.
 *
 * Everything is same-origin: the page is served by the engine itself, so the
 * `HttpOnly` cookie rides along and no token is ever visible to script. In dev the
 * vite proxy fakes that (see vite.config.ts) rather than the engine relaxing its
 * origin guard.
 */

import type { Request, Response, SpacesReply } from "./types";

/** A refusal from the engine, carrying its own words. */
export class LaitError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "LaitError";
    this.status = status;
  }
}

/**
 * A destructive verb wants its question asked first.
 *
 * The engine hands back `cli::destructive_question`'s own string — the same words
 * the CLI prompts with — so the modal and the terminal cannot disagree about what
 * is dangerous. Callers catch this, ask, and retry with `confirm`.
 */
export class ConfirmRequired extends Error {
  readonly question: string;
  constructor(question: string) {
    super(question);
    this.name = "ConfirmRequired";
    this.question = question;
  }
}

async function parse(r: globalThis.Response): Promise<unknown> {
  return r.json().catch(() => null);
}

/** The spaces picker. Supervisor-level: not a control-plane `Request`. */
export async function spaces(signal?: AbortSignal): Promise<SpacesReply> {
  const r = await fetch("/api/spaces", { credentials: "same-origin", ...(signal ? { signal } : {}) });
  const body = (await parse(r)) as SpacesReply | { kind: "error"; message: string } | null;
  if (!r.ok || (body && "kind" in body && body.kind === "error")) {
    throw new LaitError(
      body && "message" in body ? body.message : `HTTP ${r.status}`,
      r.status,
    );
  }
  if (!body) throw new LaitError("no reply", r.status);
  return body as SpacesReply;
}

/**
 * Send one control-plane `Request` to one space's daemon.
 *
 * The request/response types are the engine's own (`src/control.rs`), not a REST
 * translation of them — which is why this cannot drift from the CLI the way the
 * old viewer's hand-written routes did.
 *
 * `confirm` is not a security boundary and is not pretending to be one: anything
 * that can send `issue_delete` can send `confirm`. It exists so a destructive verb
 * cannot fire by accident, which is exactly what the CLI's prompt buys.
 */
export async function rpc<R extends Response = Response>(
  space: string,
  request: Request,
  opts: { confirm?: boolean; signal?: AbortSignal } = {},
): Promise<R> {
  const qs = opts.confirm ? "?confirm=true" : "";
  const r = await fetch(`/api/spaces/${encodeURIComponent(space)}/rpc${qs}`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request),
    ...(opts.signal ? { signal: opts.signal } : {}),
  });
  const body = (await parse(r)) as Record<string, unknown> | null;

  if (r.status === 409 && body?.kind === "confirm_required") {
    throw new ConfirmRequired(String(body.question ?? "Are you sure?"));
  }
  if (!r.ok || body?.kind === "error") {
    throw new LaitError(String(body?.message ?? `HTTP ${r.status}`), r.status);
  }
  if (!body) throw new LaitError("no reply", r.status);
  return body as R;
}
