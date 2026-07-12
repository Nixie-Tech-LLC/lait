import type { IncomingMessage, ServerResponse } from "node:http";
import QRCode from "qrcode";
import { runLait, runLaitRaw, LaitError, laitBinInfo } from "./lait";

// Parse `lait invite` raw output (two lines: bare ticket, then lait://join/URL).
async function inviteInfo(): Promise<{ ticket: string; url: string; qr: string }> {
  const lines = await runLaitRaw(["invite"]);
  const url = lines.find((l) => l.startsWith("lait://")) || "";
  const ticket =
    lines.find((l) => !l.startsWith("lait://") && !l.startsWith("(")) || "";
  if (!ticket && !url) throw new LaitError("could not parse invite output", 502);
  const qr = await QRCode.toString(url || ticket, {
    type: "svg",
    margin: 1,
    color: { dark: "#e6e7ea", light: "#00000000" },
  });
  return { ticket, url: url || `lait://join/${ticket}`, qr };
}

type Handler = (
  req: IncomingMessage,
  res: ServerResponse,
  next: (err?: unknown) => void,
) => void;

function send(res: ServerResponse, code: number, body: unknown) {
  const payload = JSON.stringify(body);
  res.statusCode = code;
  res.setHeader("content-type", "application/json; charset=utf-8");
  res.setHeader("cache-control", "no-store");
  res.end(payload);
}

function readJsonBody(req: IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > 4 * 1024 * 1024) {
        reject(new LaitError("request body too large", 413));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8").trim();
      if (!raw) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new LaitError("invalid JSON body", 400));
      }
    });
    req.on("error", reject);
  });
}

// Optional-flag helper: append `[flag, value]` only when value is a non-empty
// string, so we never pass empty `--title ""` etc.
function flag(name: string, value: unknown): string[] {
  if (value === undefined || value === null) return [];
  const s = String(value);
  return s.length ? [name, s] : [];
}

function boolFlag(name: string, value: unknown): string[] {
  return value ? [name] : [];
}

/**
 * The viewer's only backend: a thin router mapping REST endpoints onto
 * `lait --json` invocations. Everything read/written here is a real lait
 * command, so the viewer can never desync from the store or corrupt the CRDT.
 */
export function laitApi(): Handler {
  return (req, res, next) => {
    const url = req.url || "";
    if (!url.startsWith("/api/")) return next();

    const method = (req.method || "GET").toUpperCase();
    const u = new URL(url, "http://localhost");
    const parts = u.pathname.split("/").filter(Boolean); // ["api", ...]
    const seg = (i: number) => decodeURIComponent(parts[i] ?? "");

    const handle = async () => {
      // ---- diagnostics -----------------------------------------------------
      if (parts[1] === "health") {
        return send(res, 200, { ok: true, lait: laitBinInfo() });
      }
      if (parts[1] === "status") {
        return send(res, 200, await runLait(["status"]));
      }

      // ---- projects --------------------------------------------------------
      if (parts[1] === "projects") {
        if (method === "GET") return send(res, 200, await runLait(["projects", "ls"]));
        if (method === "POST") {
          const b = await readJsonBody(req);
          if (!b.name || !b.key)
            throw new LaitError("name and key are required", 400);
          return send(
            res,
            200,
            await runLait(["projects", "new", String(b.name), "--key", String(b.key)]),
          );
        }
      }

      // ---- labels ----------------------------------------------------------
      if (parts[1] === "labels") {
        if (method === "GET") return send(res, 200, await runLait(["labels", "ls"]));
        if (method === "POST") {
          const b = await readJsonBody(req);
          if (!b.name) throw new LaitError("name is required", 400);
          return send(
            res,
            200,
            await runLait(["labels", "new", String(b.name), ...flag("--color", b.color)]),
          );
        }
      }

      // ---- board -----------------------------------------------------------
      if (parts[1] === "board" && parts[2] && method === "GET") {
        return send(res, 200, await runLait(["board", seg(2)]));
      }

      // ---- activity --------------------------------------------------------
      if (parts[1] === "activity" && method === "GET") {
        const since = u.searchParams.get("since") || "0";
        return send(res, 200, await runLait(["activity", "--since", since]));
      }

      // ---- invites & membership -------------------------------------------
      if (parts[1] === "invite" && method === "GET") {
        return send(res, 200, { kind: "invite", ...(await inviteInfo()) });
      }

      if (parts[1] === "members") {
        if (method === "GET") return send(res, 200, await runLait(["members", "ls"]));
        if (method === "POST") {
          const b = await readJsonBody(req);
          if (!b.who) throw new LaitError("who (a member id) is required", 400);
          return send(
            res,
            200,
            await runLait([
              "members",
              "add",
              String(b.who),
              ...boolFlag("--admin", b.admin),
            ]),
          );
        }
      }

      // Pending join requests: Join events from the daemon log whose id is not
      // already a member. The daemon logs an EventKind::Join (with the peer's id
      // + nick) whenever someone runs `lait connect/join` against our ticket.
      if (parts[1] === "join-requests" && method === "GET") {
        const [log, mem] = await Promise.all([
          runLait(["log"]),
          runLait(["members", "ls"]),
        ]);
        const memberKeys = new Set(
          (mem.members || []).map((m: any) => String(m.key)),
        );
        const seen = new Set<string>();
        const pending: { id: string; nick: string; ts: number }[] = [];
        // newest first
        for (const e of (log.events || []).slice().reverse()) {
          if (e.kind !== "join") continue;
          if (memberKeys.has(e.id) || seen.has(e.id)) continue;
          seen.add(e.id);
          pending.push({ id: e.id, nick: e.nick, ts: e.ts });
        }
        return send(res, 200, { kind: "join_requests", requests: pending });
      }

      // ---- issues ----------------------------------------------------------
      if (parts[1] === "issues") {
        // collection
        if (!parts[2]) {
          if (method === "GET") {
            const project = u.searchParams.get("project");
            const status = u.searchParams.get("status");
            const label = u.searchParams.get("label");
            const mine = u.searchParams.get("mine");
            // Default to --all so Done/every-status rows are returned; the UI
            // filters tombstones out of view.
            const args = [
              "ls",
              ...flag("-p", project && project !== "all" ? project : ""),
              ...flag("--status", status),
              ...flag("--label", label),
              ...boolFlag("--mine", mine === "1" || mine === "true"),
              "--all",
            ];
            return send(res, 200, await runLait(args));
          }
          if (method === "POST") {
            const b = await readJsonBody(req);
            if (!b.title) throw new LaitError("title is required", 400);
            const labels: string[] = Array.isArray(b.labels) ? b.labels : [];
            const assignees: string[] = Array.isArray(b.assignees) ? b.assignees : [];
            const args = [
              "new",
              String(b.title),
              ...flag("-p", b.project),
              ...flag("-P", b.priority),
              ...flag("-b", b.body),
              ...labels.flatMap((l) => ["-l", String(l)]),
              ...assignees.flatMap((a) => ["-a", String(a)]),
            ];
            return send(res, 200, await runLait(args));
          }
        }

        // single issue: /api/issues/:reff[/action]
        const reff = seg(2);
        const action = parts[3];

        if (!action) {
          if (method === "GET") return send(res, 200, await runLait(["show", reff]));
          if (method === "PATCH") {
            const b = await readJsonBody(req);
            const args = [
              "edit",
              reff,
              ...flag("--title", b.title),
              ...flag("--status", b.status),
              ...flag("--priority", b.priority),
            ];
            if (args.length === 2) throw new LaitError("no fields to edit", 400);
            return send(res, 200, await runLait(args));
          }
          if (method === "DELETE") return send(res, 200, await runLait(["delete", reff]));
        }

        if (action === "comment" && method === "POST") {
          const b = await readJsonBody(req);
          if (!b.body) throw new LaitError("comment body is required", 400);
          return send(res, 200, await runLait(["comment", reff, String(b.body)]));
        }

        if (action === "move" && method === "POST") {
          const b = await readJsonBody(req);
          const args = [
            "move",
            reff,
            ...flag("-p", b.project),
            ...boolFlag("--top", b.top),
            ...boolFlag("--bottom", b.bottom),
            ...flag("--before", b.before),
            ...flag("--after", b.after),
          ];
          return send(res, 200, await runLait(args));
        }

        if (action === "assign" && method === "POST") {
          const b = await readJsonBody(req);
          const who: string[] = Array.isArray(b.who) ? b.who.map(String) : [];
          if (!who.length) throw new LaitError("who is required", 400);
          return send(
            res,
            200,
            await runLait(["assign", reff, ...who, ...boolFlag("--remove", b.remove)]),
          );
        }

        if (action === "label" && method === "POST") {
          const b = await readJsonBody(req);
          const add: string[] = Array.isArray(b.add) ? b.add.map(String) : [];
          const remove: string[] = Array.isArray(b.remove) ? b.remove.map(String) : [];
          const tokens = [...add.map((l) => `+${l}`), ...remove.map((l) => `-${l}`)];
          if (!tokens.length) throw new LaitError("add or remove is required", 400);
          return send(res, 200, await runLait(["label", reff, ...tokens]));
        }
      }

      throw new LaitError(`no route for ${method} ${u.pathname}`, 404);
    };

    handle().catch((err) => {
      const code = err instanceof LaitError ? err.code : 500;
      send(res, code, { kind: "error", message: String(err?.message || err) });
    });
  };
}
