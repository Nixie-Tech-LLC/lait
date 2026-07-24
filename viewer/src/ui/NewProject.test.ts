import { describe, expect, it } from "vitest";
import { deriveKey, projectKeyProblem } from "./NewProject";

describe("project identity guidance", () => {
  it("derives legible keys without overwriting validation rules", () => {
    expect(deriveKey("Design System")).toBe("DS");
    expect(deriveKey("Web 2.0")).toBe("W");
    expect(deriveKey("Engineering")).toBe("ENG");
  });

  it("flags malformed and duplicate keys before submission", () => {
    expect(projectKeyProblem("WEB2", [])).toContain("letters");
    expect(projectKeyProblem("viewerlong", [])).toContain("1–8");
    expect(projectKeyProblem("view", ["VIEW"])).toContain("already");
    expect(projectKeyProblem("NEW", ["VIEW"])).toBeNull();
  });
});
