import { beforeEach, describe, expect, it } from "vitest";

import { clearDraft, loadDraft, saveDraft } from "./drafts";

describe("private local drafts", () => {
  beforeEach(() => localStorage.clear());

  it("scopes drafts by canonical space, subject, and kind", () => {
    saveDraft("spc_a", "iss_1", "comment", "hello");
    saveDraft("spc_a", "iss_1", "title", "Recovered title");
    expect(loadDraft("spc_a", "iss_1", "comment")).toBe("hello");
    expect(loadDraft("spc_a", "iss_1", "title")).toBe("Recovered title");
    expect(loadDraft("spc_b", "iss_1", "comment")).toBe("");
    expect(loadDraft("spc_a", "iss_1", "description")).toBe("");
  });

  it("removes empty and explicitly cleared drafts", () => {
    saveDraft("spc_a", "iss_1", "comment", "hello");
    clearDraft("spc_a", "iss_1", "comment");
    expect(loadDraft("spc_a", "iss_1", "comment")).toBe("");
  });
});
