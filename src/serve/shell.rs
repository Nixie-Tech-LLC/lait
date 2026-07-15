//! The served browser shell.
//!
//! Deliberately one inert string. This slice exists to prove the two things that
//! carry risk — the loopback gate and the N-daemon supervisor — and a build
//! pipeline would only obscure whether they work. The real client is the React
//! app; when it lands, this constant is replaced by its bundle (embedded in the
//! binary, so `lait serve` stays a single self-contained artifact and the SPA
//! stays same-origin, which is what makes the `Origin` allowlist enforceable).
//!
//! It reads the same DTOs the CLI does and follows the same doorbell discipline
//! as the TUI: a ring is a dirty *flag*, so refetch the projection — never patch
//! from the frame (UI.md §4.2).

pub const HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>lait</title>
<style>
  :root { color-scheme: light dark; --bg:#fff; --fg:#111; --mut:#666; --line:#e4e4e7; --card:#fafafa; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#0c0c0e; --fg:#e8e8ea; --mut:#8a8a92; --line:#26262b; --card:#141418; }
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:14px/1.5 ui-sans-serif,system-ui,-apple-system,sans-serif; display:flex; height:100vh; }
  aside { width:260px; border-right:1px solid var(--line); padding:16px; overflow-y:auto; flex:none; }
  main { flex:1; padding:16px; overflow:auto; }
  h1 { font-size:13px; text-transform:uppercase; letter-spacing:.08em; color:var(--mut); margin:0 0 12px; }
  .space { padding:8px 10px; border-radius:6px; cursor:pointer; border:1px solid transparent; }
  .space:hover { background:var(--card); }
  .space[aria-selected="true"] { background:var(--card); border-color:var(--line); }
  .space .nm { font-weight:600; }
  .space .meta { color:var(--mut); font-size:12px; display:flex; gap:6px; align-items:center; }
  .dot { width:6px; height:6px; border-radius:50%; display:inline-block; }
  .up{background:#22c55e} .idle{background:#a1a1aa} .missing{background:#ef4444}
  .agent { font-size:11px; border:1px solid var(--line); border-radius:4px; padding:0 4px; color:var(--mut); }
  .sect { font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:var(--mut); margin:14px 0 6px; }
  .cols { display:flex; gap:12px; align-items:flex-start; overflow-x:auto; }
  .col { flex:0 0 260px; }
  .col h2 { font-size:12px; margin:0 0 8px; display:flex; gap:6px; align-items:center; }
  .count { color:var(--mut); font-weight:400; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:6px; padding:8px 10px; margin-bottom:6px; }
  .card .reff { color:var(--mut); font-size:12px; font-family:ui-monospace,monospace; }
  .empty, .err { color:var(--mut); padding:8px 0; }
  .err { color:#ef4444; }
  .live { font-size:12px; color:var(--mut); float:right; }
</style>
</head>
<body>
<aside>
  <h1>Spaces</h1>
  <div id="spaces">loading…</div>
</aside>
<main>
  <span class="live" id="live"></span>
  <div id="board" class="empty">Pick a space.</div>
</main>
<script>
const $ = (id) => document.getElementById(id);
let current = null;
let spacesCache = [];

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c]));

async function api(path) {
  // Same-origin, so the HttpOnly cookie rides along and no token is ever in JS.
  const r = await fetch(path, { credentials: "same-origin" });
  const body = await r.json().catch(() => null);
  if (!r.ok || (body && body.kind === "error")) {
    throw new Error((body && body.message) || `HTTP ${r.status}`);
  }
  return body;
}

// The control plane, verbatim — the same `Request` the CLI sends. A 409 means a
// destructive verb wants its question asked; the question is the CLI's own, so
// the modal and the terminal say the same thing.
async function rpc(space, request, confirmed) {
  const r = await fetch(`/api/spaces/${space}/rpc${confirmed ? "?confirm=true" : ""}`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request),
  });
  const body = await r.json().catch(() => null);
  if (r.status === 409 && body && body.kind === "confirm_required") {
    if (!confirm(body.question)) return null;
    return rpc(space, request, true);
  }
  if (!r.ok || (body && body.kind === "error")) {
    throw new Error((body && body.message) || `HTTP ${r.status}`);
  }
  return body;
}

async function loadSpaces() {
  try {
    const { spaces } = await api("/api/spaces");
    spacesCache = spaces;
    if (!spaces.length) {
      $("spaces").innerHTML = '<div class="empty">No spaces yet.<br>`lait init` or `lait join`.</div>';
      return;
    }
    // Agents are listed for observability, but never silently mixed in with your
    // own: their daemon runs on the agent's key, so the row says whose it is.
    const row = (s) => `
      <div class="space" role="option" data-id="${esc(s.id)}" aria-selected="${s.id === current}">
        <div class="nm">${esc(s.name || s.workspace)}</div>
        <div class="meta"><span class="dot ${esc(s.status)}"></span>${esc(s.status)} · ${esc(s.origin)}
          ${s.identity.kind === "agent" ? `<span class="agent">${esc(s.identity.name)}</span>` : ""}
        </div>
      </div>`;
    const mine = spaces.filter((s) => s.identity.kind !== "agent");
    const agents = spaces.filter((s) => s.identity.kind === "agent");
    $("spaces").innerHTML =
      mine.map(row).join("") +
      (agents.length ? `<div class="sect">Agents</div>` + agents.map(row).join("") : "");
    for (const el of document.querySelectorAll(".space")) {
      el.onclick = () => select(el.dataset.id);
    }
    // Selecting attaches a daemon, and attaching an agent brings that agent
    // *online*. So auto-select only your own single unambiguous space — never an
    // agent, which must be an explicit click.
    if (!current && mine.length === 1) select(mine[0].id);
  } catch (e) {
    $("spaces").innerHTML = `<div class="err">${esc(e.message)}</div>`;
  }
}

async function select(id) {
  current = id;
  for (const el of document.querySelectorAll(".space")) {
    el.setAttribute("aria-selected", String(el.dataset.id === id));
  }
  await loadBoard();
}

async function loadBoard() {
  if (!current) return;
  try {
    // `project: null` is legitimate — the daemon's choose-project chain resolves
    // the view, so the picker needn't know a project to show a board.
    const b = await rpc(current, { cmd: "board", project: null, project_hint: null });
    if (b.kind !== "board") throw new Error("unexpected reply");
    const ro = readOnly();
    $("board").className = "";
    $("board").innerHTML =
      `<h1>${esc(b.project.name)}${ro ? ` — read-only (${esc(ro)}'s space)` : ""}</h1>` +
      (ro ? "" : `<button id="add">+ New issue</button> `) +
      `<div class="cols">` +
      b.columns.map((c) => `
        <div class="col">
          <h2><span class="dot" style="background:${esc(c.state.color)}"></span>
              ${esc(c.state.name)} <span class="count">${c.rows.length}</span></h2>
          ${c.rows.filter((r) => !r.tombstone).map((r) => `
            <div class="card" data-reff="${esc(r.reff)}">
              <div>${esc(r.title)}</div>
              <div class="reff">${esc(r.key_alias || r.reff)}
                ${ro ? "" : `<a href="#" class="del" data-reff="${esc(r.reff)}">delete</a>`}</div>
            </div>`).join("") || '<div class="empty">—</div>'}
        </div>`).join("") + "</div>";
    if (!ro) {
      $("add").onclick = async () => {
        const title = prompt("Issue title");
        if (!title) return;
        // Every other field is `serde(default)`; omitting `project` lets the
        // daemon's choose-project chain decide, same as bare `lait new`.
        await write({ cmd: "issue_new", title });
      };
      for (const el of document.querySelectorAll(".del")) {
        el.onclick = async (ev) => {
          ev.preventDefault();
          await write({ cmd: "issue_delete", reff: el.dataset.reff });
        };
      }
    }
  } catch (e) {
    $("board").className = "err";
    $("board").textContent = e.message;
  }
}

// Whose space this is, if it isn't ours — agent spaces are observable, not
// operable, so the UI must not offer writes it knows will be refused.
function readOnly() {
  const s = spacesCache.find((x) => x.id === current);
  return s && s.identity.kind === "agent" ? s.identity.name : null;
}

// Writes need no explicit refetch: the daemon rings, and the doorbell handler
// reloads. Failure is the only thing worth reporting here.
async function write(request) {
  try {
    await rpc(current, request);
  } catch (e) {
    $("board").className = "err";
    $("board").textContent = e.message;
  }
}

// The doorbell is a dirty flag, never state: refetch the projection it names.
// One EventSource covers every attached space, so filter by the space tag.
const es = new EventSource("/api/events", { withCredentials: true });
es.onopen = () => ($("live").textContent = "live");
es.onerror = () => ($("live").textContent = "reconnecting…");
es.addEventListener("doorbell", (ev) => {
  const d = JSON.parse(ev.data);
  if (d.space !== current) return;
  loadBoard();
  if (d.dirty_catalog && d.dirty_catalog.length) loadSpaces();
});
// Frames were dropped; rebaseline rather than trust our view (UI.md §4.1).
es.addEventListener("lagged", () => { loadSpaces(); loadBoard(); });

loadSpaces();
</script>
</body>
</html>
"##;
