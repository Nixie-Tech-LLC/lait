import type {
  BoardView,
  InviteInfo,
  IssueView,
  JoinRequest,
  LabelDto,
  MemberDto,
  Priority,
  ProjectDto,
  Row,
  StatusInfo,
} from "./types";

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: init?.body ? { "content-type": "application/json" } : undefined,
  });
  const text = await res.text();
  let body: any = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`bad response from ${path}: ${text.slice(0, 200)}`);
  }
  if (!res.ok || body?.kind === "error") {
    throw new Error(body?.message || `request failed (${res.status})`);
  }
  return body as T;
}

const enc = encodeURIComponent;

export const api = {
  status: () => req<StatusInfo>("/api/status"),

  projects: () =>
    req<{ projects: ProjectDto[] }>("/api/projects").then((r) => r.projects),
  createProject: (name: string, key: string) =>
    req<{ reff?: string }>("/api/projects", {
      method: "POST",
      body: JSON.stringify({ name, key }),
    }),

  labels: () => req<{ labels: LabelDto[] }>("/api/labels").then((r) => r.labels),

  issues: (opts: { project?: string; status?: string } = {}) => {
    const p = new URLSearchParams();
    if (opts.project && opts.project !== "all") p.set("project", opts.project);
    if (opts.status) p.set("status", opts.status);
    const qs = p.toString();
    return req<{ rows: Row[] }>(`/api/issues${qs ? `?${qs}` : ""}`).then(
      (r) => r.rows,
    );
  },

  issue: (reff: string) => req<IssueView>(`/api/issues/${enc(reff)}`),

  createIssue: (input: {
    title: string;
    project?: string;
    priority?: Priority;
    body?: string;
    labels?: string[];
  }) =>
    req<{ reff: string }>("/api/issues", {
      method: "POST",
      body: JSON.stringify(input),
    }),

  editIssue: (
    reff: string,
    patch: { title?: string; status?: string; priority?: Priority },
  ) =>
    req(`/api/issues/${enc(reff)}`, {
      method: "PATCH",
      body: JSON.stringify(patch),
    }),

  deleteIssue: (reff: string) =>
    req(`/api/issues/${enc(reff)}`, { method: "DELETE" }),

  comment: (reff: string, body: string) =>
    req(`/api/issues/${enc(reff)}/comment`, {
      method: "POST",
      body: JSON.stringify({ body }),
    }),

  board: (project: string) => req<BoardView>(`/api/board/${enc(project)}`),

  invite: () => req<InviteInfo>("/api/invite"),

  members: () =>
    req<{ members: MemberDto[] }>("/api/members").then((r) => r.members),

  joinRequests: () =>
    req<{ requests: JoinRequest[] }>("/api/join-requests").then((r) => r.requests),

  addMember: (who: string, admin = false) =>
    req("/api/members", {
      method: "POST",
      body: JSON.stringify({ who, admin }),
    }),
};
