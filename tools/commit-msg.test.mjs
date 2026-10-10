import { describe, expect, it } from "vitest";
import { validateMessage } from "./commit-msg.mjs";

describe("commit messages", () => {
  it("accepts conventional headers", () => {
    for (const m of [
      "feat: add overview",
      "fix(api): handle empty report",
      "chore!: drop node 20",
      "docs(readme): add install steps",
    ]) {
      expect(validateMessage(m)).toEqual([]);
    }
  });
  it("rejects bad headers", () => {
    for (const m of [
      "Add overview",
      "feature: x",
      "feat:missing space",
      "feat: ends with period.",
      "feat(Scope): caps scope",
    ]) {
      expect(validateMessage(m).length).toBeGreaterThan(0);
    }
  });
  it("rejects over-long headers", () => {
    expect(validateMessage(`feat: ${"x".repeat(80)}`).join()).toContain("limit");
  });
  it("needs a blank line before the body", () => {
    expect(validateMessage("feat: x\nbody").join()).toContain("blank line");
    expect(validateMessage("feat: x\n\nbody")).toEqual([]);
  });
  it("ignores git comments and merge commits", () => {
    expect(validateMessage("feat: x\n# comment")).toEqual([]);
    expect(validateMessage("Merge branch 'a' into b")).toEqual([]);
  });
});
