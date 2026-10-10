import { describe, expect, it } from "vitest";
import { checkRelease, notesFor } from "./release-notes.mjs";

const CHANGELOG = `# Changelog

## [Unreleased]

## [0.2.0] - 2026-11-01

### Added

- Second thing.

## [0.1.0] - 2026-10-20

### Added

- First thing.
- Another thing.

### Fixed

- A bug.
`;

describe("notesFor", () => {
  it("returns the section of one version, without its heading", () => {
    expect(notesFor(CHANGELOG, "0.1.0")).toBe("### Added\n\n- First thing.\n- Another thing.\n\n### Fixed\n\n- A bug.");
  });
  it("stops at the next version heading", () => {
    expect(notesFor(CHANGELOG, "0.2.0")).toBe("### Added\n\n- Second thing.");
  });
  it("is empty for a version that has no section", () => {
    expect(notesFor(CHANGELOG, "9.9.9")).toBe("");
  });
  it("does not mistake 0.1.0 for 0.1.01", () => {
    expect(notesFor("## [0.1.01]\n\n- x\n", "0.1.0")).toBe("");
  });
});

describe("checkRelease", () => {
  const ok = { tag: "v0.1.0", version: "0.1.0", changelog: CHANGELOG };
  it("accepts a tag that matches the package version and has release notes", () => {
    expect(checkRelease(ok)).toEqual([]);
  });
  it("rejects a tag that is not v<version>", () => {
    expect(checkRelease({ ...ok, tag: "v0.1.1" })[0]).toContain("does not match");
    expect(checkRelease({ ...ok, tag: "0.1.0" })[0]).toContain("does not match");
  });
  it("rejects a development version", () => {
    expect(checkRelease({ ...ok, tag: "v0.1.0-dev.3", version: "0.1.0-dev.3" })).toContain(
      "version 0.1.0-dev.3 is a development version",
    );
  });
  it("rejects a version with no notes in the changelog", () => {
    expect(checkRelease({ ...ok, tag: "v0.3.0", version: "0.3.0" })).toContain("CHANGELOG.md has no notes for 0.3.0");
  });
});
