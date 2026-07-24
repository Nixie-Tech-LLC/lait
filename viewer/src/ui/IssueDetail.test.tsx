import { act, StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { IssueView, ProjectDto, WorkflowState } from "../types";
import { WorldViewStoreProvider } from "../core/worldViewReact";
import { projectKeys, ProjectViewerStore, ProjectViewerStoreProvider } from "../projectStore";
import { IssueDetail } from "./IssueDetail";
import { TooltipProvider } from "./primitives";

const rpcMock = vi.hoisted(() => vi.fn());
vi.mock("../api", () => ({ rpc: rpcMock }));

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean })
  .IS_REACT_ACT_ENVIRONMENT = true;

describe("IssueDetail loading", () => {
  let host: HTMLDivElement | null = null;
  let root: ReturnType<typeof createRoot> | null = null;

  afterEach(() => {
    if (root) act(() => root?.unmount());
    host?.remove();
    root = null;
    host = null;
    rpcMock.mockReset();
  });

  it("renders the issue document without waiting for history or relations", async () => {
    const never = new Promise<never>(() => undefined);
    let resolveView!: (value: IssueView & { kind: "issue" }) => void;
    const view = new Promise<IssueView & { kind: "issue" }>((resolve) => {
      resolveView = resolve;
    });
    rpcMock.mockImplementation((_space: string, request: { cmd: string }) => {
      if (request.cmd === "issue_view") return view;
      if (request.cmd === "milestone_list") {
        return Promise.resolve({ kind: "milestones", milestones: [] });
      }
      if (request.cmd === "history" || request.cmd === "issue_graph") return never;
      throw new Error(`Unexpected request: ${request.cmd}`);
    });

    host = document.createElement("div");
    document.body.append(host);
    root = createRoot(host);
    const store = new ProjectViewerStore(rpcMock);
    store.resources.set(projectKeys.row("local", issue.reff), {
      reff: issue.reff,
      doc_id: issue.doc_id,
      project_id: issue.project_id,
      key_alias: issue.key_alias,
      title: issue.title,
      status: issue.status,
      priority: issue.priority,
      assignee_summary: "",
      assignees: issue.assignees,
      tombstone: false,
      provisional: false,
    });

    act(() => {
      root?.render(
        <WorldViewStoreProvider store={store.resources}>
          <ProjectViewerStoreProvider store={store}>
            <StrictMode>
              <TooltipProvider>
                <IssueDetail
            spaceId="local"
            canonicalSpaceId="ws_test"
            reff={issue.reff}
            states={[state]}
            members={[]}
            labels={[]}
            projects={[project]}
            readOnly
            tombstone={false}
            openField={null}
            onOpenField={() => undefined}
            onError={vi.fn()}
            onDelete={() => undefined}
            onPredict={async () => true}
            onNavigate={() => undefined}
            onClose={() => undefined}
            focused
            onToggleFocus={() => undefined}
            onOpenProject={() => undefined}
                />
              </TooltipProvider>
            </StrictMode>
          </ProjectViewerStoreProvider>
        </WorldViewStoreProvider>,
      );
    });

    expect(host.textContent).not.toContain("Loading issue");
    expect(host.querySelector<HTMLTextAreaElement>('[aria-label="Title"]')?.value)
      .toBe(issue.title);
    // The trail is the issue's lineage — its project, then itself — and the leaf
    // is the only crumb that doesn't navigate.
    const breadcrumb = host.querySelector('nav[aria-label="Breadcrumb"]');
    expect(breadcrumb?.textContent).toContain("Test project");
    expect(breadcrumb?.querySelectorAll("button")).toHaveLength(1);
    expect(breadcrumb?.querySelector('[aria-current="page"]')?.textContent)
      .toContain(`${issue.key_alias}${issue.title}`);
    await act(async () => {
      await Promise.resolve();
    });
    expect(rpcMock.mock.calls.filter(([, request]) => request.cmd === "issue_view")).toHaveLength(1);
    await act(async () => {
      resolveView({ kind: "issue", ...issue });
      await new Promise((resolve) => setTimeout(resolve, 0));
    });

    expect(host.textContent).not.toContain("Loading issue");
  });
});

const state: WorkflowState = {
  id: "done",
  name: "Done",
  category: "done",
  color: "green",
};

const project: ProjectDto = {
  id: "prj_test",
  name: "Test project",
  key: "TEST",
  color: "blue",
};

const issue: IssueView = {
  schema_version: 1,
  reff: "iss_test",
  doc_id: "doc_test",
  space_id: "ws_test",
  project_id: project.id,
  project_key: project.key,
  key_alias: "TEST-1",
  title: "Primary content is ready",
  description: "",
  status: state.id,
  priority: "none",
  assignees: [],
  labels: [],
  label_names: [],
  comments: [],
  created_by: "actor_test",
  created_at: 1,
  provisional: false,
};
