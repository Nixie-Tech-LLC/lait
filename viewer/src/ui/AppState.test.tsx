import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it } from "vitest";

import {
  ApplicationState,
  classifyFailure,
  InlineError,
  LoadingState,
  recoveryDiagnostics,
  recoveryForError,
  trustSummary,
} from "./AppState";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean })
  .IS_REACT_ACT_ENVIRONMENT = true;

describe("application state vocabulary", () => {
  let host: HTMLDivElement | null = null;
  let root: ReturnType<typeof createRoot> | null = null;

  afterEach(() => {
    if (root) act(() => root?.unmount());
    host?.remove();
    root = null;
    host = null;
  });

  it("announces loading as busy status without treating it as an error", () => {
    render(<LoadingState title="Loading issues" body="Reading local data." />);
    const state = host!.querySelector('[data-application-state="loading"]');
    expect(state?.getAttribute("role")).toBe("status");
    expect(state?.getAttribute("aria-busy")).toBe("true");
    expect(state?.textContent).toContain("Loading issues");
  });

  it("distinguishes filtered empty from ordinary empty", () => {
    render(<ApplicationState kind="filtered-empty" title="No matching issues" />);
    expect(host!.querySelector('[data-application-state="filtered-empty"]')).toBeTruthy();
  });

  it("uses an alert only for an error state", () => {
    render(<ApplicationState kind="error" title="Could not load" />);
    expect(host!.querySelector('[role="alert"]')?.textContent).toContain("Could not load");
  });

  it("gives retry states an explicit recoverable identity", () => {
    render(<ApplicationState kind="retry" title="Connection interrupted" action={<button>Try again</button>} />);
    expect(host!.querySelector('[data-application-state="retry"] button')?.textContent).toBe("Try again");
  });

  it("offers contextual recovery, diagnostics, and dismissal", () => {
    let retried = 0;
    let copied = 0;
    let dismissed = 0;
    render(
      <InlineError
        title="Local service unavailable"
        message="Network request failed"
        retryLabel="Reconnect"
        onRetry={() => retried++}
        onCopy={() => copied++}
        onDismiss={() => dismissed++}
      />,
    );

    const buttons = [...host!.querySelectorAll("button")];
    act(() => buttons.find((button) => button.textContent?.includes("Reconnect"))?.click());
    act(() => buttons.find((button) => button.textContent?.includes("Copy details"))?.click());
    act(() => buttons.find((button) => button.getAttribute("aria-label") === "Dismiss error")?.click());
    expect([retried, copied, dismissed]).toEqual([1, 1, 1]);
  });

  it("classifies connection and authorization recovery into useful actions", () => {
    expect(recoveryForError("Failed to fetch daemon status")).toEqual({
      title: "Local service unavailable",
      retryLabel: "Reconnect",
    });
    expect(recoveryForError("Unauthorized: space is read-only")).toEqual({
      title: "Read-only space",
      retryLabel: "Refresh",
    });
    expect(recoveryForError("Unexpected projection failure")).toEqual({
      title: "Something didn’t finish",
      retryLabel: "Retry",
    });
  });

  it("classifies the complete viewer failure vocabulary", () => {
    expect(classifyFailure("network offline")).toBe("offline");
    expect(classifyFailure("schema version incompatible")).toBe("incompatible");
    expect(classifyFailure("unauthorized")).toBe("authorization");
    expect(classifyFailure("agent is read-only")).toBe("read-only");
    expect(classifyFailure("unknown issue reference")).toBe("invalid-reference");
    expect(classifyFailure("stale expected revision")).toBe("stale");
    expect(classifyFailure("ambiguous: multiple matches")).toBe("ambiguity");
    expect(classifyFailure("concurrent conflict")).toBe("conflict");
    expect(classifyFailure("provisional body still arriving")).toBe("provisional");
    expect(classifyFailure("corrupt undecodable record")).toBe("corrupt");
    expect(classifyFailure("validation rejected")).toBe("rejected");
    expect(classifyFailure("queued pending synchronization")).toBe("pending-sync");
  });

  function render(node: React.ReactNode) {
    host = document.createElement("div");
    document.body.append(host);
    root = createRoot(host);
    act(() => root?.render(node));
  }
});

describe("local trust summary", () => {
  it("makes locally safe offline data explicit", () => {
    expect(trustSummary("retrying", true, 0, false)).toBe("Offline · local data safe");
  });

  it("prioritizes degraded recovery over connectivity", () => {
    expect(trustSummary("live", true, 2, true)).toBe("Recovery needs attention");
  });

  it("reports reachability without claiming convergence", () => {
    expect(trustSummary("live", true, 2, false)).toBe("2 peers");
  });

  it("produces copyable recovery detail without inventing repair success", () => {
    expect(recoveryDiagnostics({
      id: "local",
      nick: "me",
      name: "Viewer",
      online_peers: 0,
      space: "ws_viewer",
      issues: 89,
      projects: 13,
      membership: "admin",
      recovery: {
        scheme: "Single",
        k: 1,
        n: 1,
        local_custody: { state: "unreadable", detail: { kind: "undecryptable", detail: "wrong key" } },
      },
      degraded_recovery: [{
        transcript: "transcript-1",
        reason: { kind: "undecryptable", detail: "wrong key" },
        is_current_authority: true,
      }],
    })).toContain("Failure: undecryptable: wrong key");
  });
});
