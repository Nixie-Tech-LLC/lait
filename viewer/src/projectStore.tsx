import { createContext, useCallback, useContext, useMemo, type ReactNode } from "react";
import { rpc as defaultRpc } from "./api";
import { applyOverlay, Overlay, type Field } from "./core/overlay";
import { useWorldResource } from "./core/worldViewReact";
import { type ResourceSnapshot, WorldViewStore } from "./core/worldViewStore";
import type {
  ActivityEvent,
  BoardView,
  GraphView,
  IssueView,
  LabelDto,
  MemberDto,
  MilestoneDto,
  Priority,
  ProjectDto,
  Request,
  Response,
  Row,
  SpaceDoorbell,
  StatusInfo,
} from "./types";

type Rpc = (space: string, request: Request) => Promise<Response>;

const part = (value: string | null | undefined) => encodeURIComponent(value ?? "_");
const prefix = (space: string) => `space:${part(space)}/`;
export const projectKeys = {
  board: (space: string, project: string | null) => `${prefix(space)}board:${part(project)}`,
  row: (space: string, reff: string) => `${prefix(space)}row:${part(reff)}`,
  issue: (space: string, reff: string) => `${prefix(space)}issue:${part(reff)}`,
  graph: (space: string, reff: string) => `${prefix(space)}graph:${part(reff)}`,
  history: (space: string, reff: string) => `${prefix(space)}history:${part(reff)}`,
  milestones: (space: string, project: string) => `${prefix(space)}milestones:${part(project)}`,
  labels: (space: string) => `${prefix(space)}labels`,
  members: (space: string) => `${prefix(space)}members`,
  projects: (space: string) => `${prefix(space)}projects`,
  status: (space: string) => `${prefix(space)}status`,
};

export interface IssueDetailSnapshot {
  readonly issue: IssueView | null;
  readonly row: Row | null;
  readonly body: ResourceSnapshot<IssueView>;
  readonly graph: ResourceSnapshot<GraphView>;
  readonly history: ResourceSnapshot<ActivityEvent[]>;
  readonly milestones: ResourceSnapshot<MilestoneDto[]>;
  readonly partial: boolean;
  readonly secondaryError: unknown | null;
}

function issueFromRow(space: string, row: Row): IssueView {
  return {
    schema_version: 3,
    reff: row.reff,
    doc_id: row.doc_id,
    space_id: space,
    project_id: row.project_id,
    project_key: row.key_alias?.split("-")[0] ?? null,
    key_alias: row.key_alias,
    title: row.title,
    description: "",
    status: row.status,
    priority: row.priority,
    assignees: row.assignees,
    labels: [],
    label_names: row.label_names ?? [],
    comments: [],
    created_by: "",
    created_at: 0,
    ...(row.due_date !== undefined ? { due_date: row.due_date } : {}),
    ...(row.estimate !== undefined ? { estimate: row.estimate } : {}),
    provisional: row.provisional,
  };
}

export class ProjectViewerStore {
  readonly resources: WorldViewStore;
  readonly overlay = new Overlay();
  private loaders = new Map<string, () => Promise<unknown>>();
  private rowsByDoc = new Map<string, Map<string, Row>>();
  private boardSelectors = new Map<string, {
    source: ResourceSnapshot<BoardView>;
    overlay: string;
    value: BoardView | null;
  }>();
  private rowSelectors = new Map<string, {
    source: ResourceSnapshot<Row>;
    overlay: string;
    value: Row | null;
  }>();
  private detailSelectors = new Map<string, {
    dependencies: readonly unknown[];
    value: IssueDetailSnapshot;
  }>();

  constructor(
    private readonly rpc: Rpc = defaultRpc,
    resources = new WorldViewStore(),
  ) {
    this.resources = resources;
  }

  selectBoard(space: string, project: string | null): BoardView | null {
    const key = projectKeys.board(space, project);
    const source = this.resources.read<BoardView>(key);
    const overlay = source.data
      ? source.data.columns.flatMap((column) => column.rows)
        .map((row) => `${row.doc_id}:${this.overlay.get(row.doc_id, "title") ?? ""}:${this.overlay.get(row.doc_id, "status") ?? ""}:${this.overlay.get(row.doc_id, "priority") ?? ""}`)
        .join("|")
      : "";
    const cached = this.boardSelectors.get(key);
    if (cached?.source === source && cached.overlay === overlay) return cached.value;
    const value = source.data ? applyOverlay(source.data, this.overlay).board : null;
    this.boardSelectors.set(key, { source, overlay, value });
    return value;
  }

  selectRow(space: string, reff: string): Row | null {
    const key = projectKeys.row(space, reff);
    const source = this.resources.read<Row>(key);
    const row = source.data;
    if (!row) return null;
    const overlay = `${this.overlay.get(row.doc_id, "title") ?? ""}:${this.overlay.get(row.doc_id, "status") ?? ""}:${this.overlay.get(row.doc_id, "priority") ?? ""}`;
    const cached = this.rowSelectors.get(key);
    if (cached?.source === source && cached.overlay === overlay) return cached.value;
    const value = !this.overlay.has(row.doc_id) ? row : {
        ...row,
        title: this.overlay.get(row.doc_id, "title") ?? row.title,
        status: this.overlay.get(row.doc_id, "status") ?? row.status,
        priority: (this.overlay.get(row.doc_id, "priority") as Priority | undefined) ?? row.priority,
      };
    this.rowSelectors.set(key, { source, overlay, value });
    return value;
  }

  selectIssueDetail(space: string, reff: string): IssueDetailSnapshot {
    const row = this.selectRow(space, reff);
    const body = this.resources.read<IssueView>(projectKeys.issue(space, reff));
    const graph = this.resources.read<GraphView>(projectKeys.graph(space, reff));
    const history = this.resources.read<ActivityEvent[]>(projectKeys.history(space, reff));
    const projectId = body.data?.project_id ?? row?.project_id;
    const milestones = projectId
      ? this.resources.read<MilestoneDto[]>(projectKeys.milestones(space, projectId))
      : this.resources.read<MilestoneDto[]>(projectKeys.milestones(space, "_unknown"));
    const selectorKey = `${space}/${reff}`;
    const dependencies = [row, body, graph, history, milestones] as const;
    const cached = this.detailSelectors.get(selectorKey);
    if (cached && cached.dependencies.every((value, index) => value === dependencies[index])) {
      return cached.value;
    }
    const base = body.data ?? (row ? issueFromRow(space, row) : null);
    const issue: IssueView | null = base && row
      ? {
          ...base,
          title: row.title,
          status: row.status,
          priority: row.priority,
          assignees: body.data?.assignees ?? row.assignees,
          label_names: body.data?.label_names ?? row.label_names ?? [],
          ...(body.data?.due_date !== undefined
            ? { due_date: body.data.due_date }
            : row.due_date !== undefined ? { due_date: row.due_date } : {}),
          ...(body.data?.estimate !== undefined
            ? { estimate: body.data.estimate }
            : row.estimate !== undefined ? { estimate: row.estimate } : {}),
        }
      : base;
    const value = {
      issue,
      row,
      body,
      graph,
      history,
      milestones,
      partial: body.data === undefined,
      secondaryError: graph.error ?? history.error ?? milestones.error,
    };
    this.detailSelectors.set(selectorKey, { dependencies, value });
    return value;
  }

  ensureBoard(space: string, project: string | null, force = false): Promise<BoardView> {
    const key = projectKeys.board(space, project);
    return this.load(key, async () => {
      const result = await this.rpc(space, { cmd: "board", project });
      if (result.kind !== "board") throw new Error("Expected board response");
      this.ingestBoard(space, result);
      return result;
    }, force);
  }

  ensureIssue(space: string, reff: string, force = false): Promise<IssueView> {
    const key = projectKeys.issue(space, reff);
    const promise = this.load(key, async () => {
      const result = await this.rpc(space, { cmd: "issue_view", reff });
      if (result.kind !== "issue") throw new Error("Expected issue response");
      this.ingestIssue(space, result);
      return result;
    }, force);
    this.resources.evict(`${prefix(space)}issue:`, 200, new Set([key]));
    return promise;
  }

  ensureGraph(space: string, reff: string, force = false): Promise<GraphView> {
    const key = projectKeys.graph(space, reff);
    const promise = this.load(key, async () => {
      const result = await this.rpc(space, { cmd: "issue_graph", reff });
      if (result.kind !== "graph") throw new Error("Expected graph response");
      for (const row of [
        ...(result.parent ? [result.parent] : []),
        ...result.children,
        ...result.links.map((link) => link.row),
        ...result.blocked_by,
      ]) this.ingestRow(space, row);
      return result;
    }, force);
    this.resources.evict(`${prefix(space)}graph:`, 50, new Set([key]));
    return promise;
  }

  ensureHistory(space: string, reff: string, force = false): Promise<ActivityEvent[]> {
    const key = projectKeys.history(space, reff);
    const promise = this.load(key, async () => {
      const result = await this.rpc(space, { cmd: "history", reff });
      if (result.kind !== "activity") throw new Error("Expected history response");
      return result.events;
    }, force);
    this.resources.evict(`${prefix(space)}history:`, 50, new Set([key]));
    return promise;
  }

  ensureMilestones(space: string, project: string, force = false): Promise<MilestoneDto[]> {
    return this.load(projectKeys.milestones(space, project), async () => {
      const result = await this.rpc(space, { cmd: "milestone_list", project });
      if (result.kind !== "milestones") throw new Error("Expected milestones response");
      return result.milestones;
    }, force);
  }

  ensureLabels(space: string, force = false): Promise<LabelDto[]> {
    return this.load(projectKeys.labels(space), async () => {
      const result = await this.rpc(space, { cmd: "label_list" });
      if (result.kind !== "labels") throw new Error("Expected labels response");
      return result.labels;
    }, force);
  }

  ensureMembers(space: string, force = false): Promise<MemberDto[]> {
    return this.load(projectKeys.members(space), async () => {
      const result = await this.rpc(space, { cmd: "members" });
      if (result.kind !== "members") throw new Error("Expected members response");
      return result.members;
    }, force);
  }

  ensureProjects(space: string, force = false): Promise<ProjectDto[]> {
    return this.load(projectKeys.projects(space), async () => {
      const result = await this.rpc(space, { cmd: "project_list" });
      if (result.kind !== "projects") throw new Error("Expected projects response");
      return result.projects;
    }, force);
  }

  ensureStatus(space: string, force = false): Promise<StatusInfo> {
    return this.load(projectKeys.status(space), async () => {
      const result = await this.rpc(space, { cmd: "status" });
      if (result.kind !== "status") throw new Error("Expected status response");
      return result;
    }, force);
  }

  ensureIssueDetail(space: string, reff: string): void {
    void this.ensureIssue(space, reff).then((issue) => {
      void this.ensureMilestones(space, issue.project_id).catch(() => undefined);
    }).catch(() => undefined);
    void this.ensureGraph(space, reff).catch(() => undefined);
    void this.ensureHistory(space, reff).catch(() => undefined);
  }

  prefetchIssue(space: string, reff: string): void {
    void this.ensureIssue(space, reff).catch(() => undefined);
  }

  async editTitle(space: string, reff: string, title: string): Promise<boolean> {
    return this.predict(space, reff, "title", title, { cmd: "issue_edit", reff, title });
  }

  async setStatus(space: string, reff: string, status: string): Promise<boolean> {
    return this.predict(space, reff, "status", status, { cmd: "issue_edit", reff, status });
  }

  async setPriority(space: string, reff: string, priority: string): Promise<boolean> {
    return this.predict(space, reff, "priority", priority, { cmd: "issue_edit", reff, priority });
  }

  async predictValue(
    space: string,
    doc: string,
    field: Field,
    value: string,
    send: () => Promise<unknown>,
  ): Promise<boolean> {
    this.overlay.set(doc, field, value);
    this.notifyRows(space, [doc]);
    try {
      await send();
      return true;
    } catch (error) {
      this.overlay.clearDoc(doc);
      this.notifyRows(space, [doc]);
      throw error;
    }
  }

  async handleDoorbell(doorbell: SpaceDoorbell): Promise<void> {
    const space = doorbell.space;
    const scope = prefix(space);
    if (doorbell.reset) {
      this.overlay.clear();
      const keys = this.resources.reset((key) => key.startsWith(scope));
      await this.refreshActive(keys);
      return;
    }

    const dirty = Object.values(doorbell.dirty_by_project).flat();
    const affectedBoards = new Set<string>();
    const dirtyResources = new Set<string>();
    for (const project of Object.keys(doorbell.dirty_by_project)) {
      for (const key of this.loaders.keys()) {
        if (key === projectKeys.board(space, project) || key === projectKeys.board(space, null)) {
          affectedBoards.add(key);
        }
      }
    }
    for (const doc of dirty) {
      const row = this.rowsByDoc.get(space)?.get(doc);
      if (!row) continue;
      dirtyResources.add(projectKeys.issue(space, row.reff));
      dirtyResources.add(projectKeys.graph(space, row.reff));
    }
    for (const key of this.loaders.keys()) {
      if (dirty.length && key.startsWith(`${scope}milestones:`)) dirtyResources.add(key);
    }
    for (const key of dirtyResources) this.resources.invalidate(key);
    for (const key of affectedBoards) this.resources.invalidate(key);
    await this.refreshActive([...affectedBoards]);
    for (const doc of dirty) this.overlay.clearDoc(doc);
    this.notifyRows(space, dirty);
    for (const key of affectedBoards) this.resources.notify(key);
    await this.refreshActive([...dirtyResources]);

    if (doorbell.dirty_catalog.length) {
      const keys = new Set<string>();
      for (const dirty of doorbell.dirty_catalog) {
        if (dirty.scope === "labels") keys.add(projectKeys.labels(space));
        if (dirty.scope === "projects") {
          keys.add(projectKeys.projects(space));
          keys.add(projectKeys.status(space));
        }
        if (dirty.scope === "acl") {
          keys.add(projectKeys.members(space));
          keys.add(projectKeys.status(space));
        }
        if (dirty.scope === "workflow" || dirty.scope === "boards") {
          for (const key of this.loaders.keys()) {
            if (!key.startsWith(`${scope}board:`)) continue;
            if (dirty.scope === "workflow" || dirty.project == null ||
                key === projectKeys.board(space, dirty.project) ||
                key === projectKeys.board(space, null)) keys.add(key);
          }
        }
      }
      keys.forEach((key) => this.resources.invalidate(key));
      await this.refreshActive([...keys]);
    }
    if (doorbell.activity_advanced) {
      const keys = [...this.loaders.keys()].filter((key) => key.startsWith(`${scope}history:`));
      keys.forEach((key) => this.resources.invalidate(key));
      await this.refreshActive(keys);
    }
  }

  expirePredictions(space: string): boolean {
    if (!this.overlay.sweep()) return false;
    for (const row of this.rowsByDoc.get(space)?.values() ?? []) {
      this.resources.notify(projectKeys.row(space, row.reff));
    }
    for (const key of this.loaders.keys()) {
      if (key.startsWith(`${prefix(space)}board:`)) this.resources.notify(key);
    }
    return true;
  }

  private ingestBoard(space: string, board: BoardView): void {
    for (const row of board.columns.flatMap((column) => column.rows)) this.ingestRow(space, row);
  }

  private ingestIssue(space: string, issue: IssueView): void {
    const existing = this.resources.read<Row>(projectKeys.row(space, issue.reff)).data;
    if (existing) {
      this.ingestRow(space, {
        ...existing,
        title: issue.title,
        status: issue.status,
        priority: issue.priority,
        assignees: issue.assignees,
        ...(issue.due_date !== undefined ? { due_date: issue.due_date } : {}),
        ...(issue.estimate !== undefined ? { estimate: issue.estimate } : {}),
        label_names: issue.label_names,
        provisional: issue.provisional,
      });
    }
  }

  private ingestRow(space: string, row: Row): void {
    const rows = this.rowsByDoc.get(space) ?? new Map<string, Row>();
    rows.set(row.doc_id, row);
    this.rowsByDoc.set(space, rows);
    this.resources.set(projectKeys.row(space, row.reff), row);
  }

  private async predict(
    space: string,
    reff: string,
    field: Field,
    value: string,
    request: Request,
  ): Promise<boolean> {
    const row = this.resources.read<Row>(projectKeys.row(space, reff)).data;
    if (!row) return false;
    this.overlay.set(row.doc_id, field, value);
    this.notifyRows(space, [row.doc_id]);
    try {
      await this.rpc(space, request);
      return true;
    } catch (error) {
      this.overlay.clearDoc(row.doc_id);
      this.notifyRows(space, [row.doc_id]);
      throw error;
    }
  }

  private notifyRows(space: string, docs: readonly string[]): void {
    for (const doc of docs) {
      const row = this.rowsByDoc.get(space)?.get(doc);
      if (row) this.resources.notify(projectKeys.row(space, row.reff));
    }
    for (const key of this.loaders.keys()) {
      if (key.startsWith(`${prefix(space)}board:`)) this.resources.notify(key);
    }
  }

  private load<T>(key: string, loader: () => Promise<T>, force: boolean): Promise<T> {
    this.loaders.set(key, loader);
    return this.resources.ensure(key, loader, { force });
  }

  private async refreshActive(keys: readonly string[]): Promise<void> {
    await Promise.all(keys.map(async (key) => {
      const loader = this.loaders.get(key);
      if (!loader || !this.resources.isActive(key)) return;
      await this.resources.ensure(key, loader, { force: true }).catch(() => undefined);
    }));
  }
}

const ProjectStoreContext = createContext<ProjectViewerStore | null>(null);

export function ProjectViewerStoreProvider({
  store,
  children,
}: {
  store: ProjectViewerStore;
  children: ReactNode;
}) {
  return <ProjectStoreContext.Provider value={store}>{children}</ProjectStoreContext.Provider>;
}

export function useProjectViewerStore(): ProjectViewerStore {
  const store = useContext(ProjectStoreContext);
  if (!store) throw new Error("ProjectViewerStoreProvider is missing");
  return store;
}

export function useProjectBoard(space: string | null, project: string | null) {
  const store = useProjectViewerStore();
  const key = space ? projectKeys.board(space, project) : "project:none/board";
  const loader = useCallback(
    () => space ? store.ensureBoard(space, project) : Promise.reject(new Error("No space")),
    [project, space, store],
  );
  const resource = useWorldResource<BoardView>(key, space ? loader : undefined);
  return useMemo(
    () => ({ resource, board: space ? store.selectBoard(space, project) : null }),
    [project, resource, space, store],
  );
}

export function useProjectRegistry<T>(
  key: string,
  loader: (() => Promise<T>) | undefined,
): ResourceSnapshot<T> {
  return useWorldResource(key, loader);
}

export function useIssueDetail(space: string, reff: string): IssueDetailSnapshot {
  const store = useProjectViewerStore();
  const row = useWorldResource<Row>(projectKeys.row(space, reff));
  const body = useWorldResource<IssueView>(
    projectKeys.issue(space, reff),
    useCallback(() => store.ensureIssue(space, reff), [reff, space, store]),
  );
  const graph = useWorldResource<GraphView>(
    projectKeys.graph(space, reff),
    useCallback(() => store.ensureGraph(space, reff), [reff, space, store]),
  );
  const history = useWorldResource<ActivityEvent[]>(
    projectKeys.history(space, reff),
    useCallback(() => store.ensureHistory(space, reff), [reff, space, store]),
  );
  const projectId = body.data?.project_id ?? row.data?.project_id;
  useWorldResource<MilestoneDto[]>(
    projectId ? projectKeys.milestones(space, projectId) : projectKeys.milestones(space, "_unknown"),
    useCallback(
      () => projectId ? store.ensureMilestones(space, projectId) : Promise.resolve([]),
      [projectId, space, store],
    ),
  );
  return useMemo(
    () => store.selectIssueDetail(space, reff),
    // The resource objects are immutable change tokens.
    [body, graph, history, reff, row, space, store, projectId],
  );
}
