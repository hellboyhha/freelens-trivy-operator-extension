import { describe, expect, it } from "vitest";
import { inspectPackage } from "./pack.mjs";

const good = {
  files: ["package/package.json", "package/LICENSE", "package/out/main/index.js", "package/out/renderer/index.js"],
  manifest: {
    main: "out/main/index.js",
    renderer: "out/renderer/index.js",
    engines: { freelens: "^1.10.0" },
    license: "MIT",
  },
  outSources: { "package/out/renderer/index.js": "export {}" },
  unpackedBytes: 1000,
};

describe("package inspection", () => {
  it("accepts a clean package", () => {
    expect(inspectPackage(good)).toEqual([]);
  });
  it("rejects stray files", () => {
    expect(inspectPackage({ ...good, files: [...good.files, "package/src/a.ts"] })).toHaveLength(1);
  });
  it("rejects a 2.x engine range and runtime dependencies", () => {
    expect(
      inspectPackage({
        ...good,
        manifest: { ...good.manifest, engines: { freelens: "^2.0.0" }, dependencies: { a: "1" } },
      }),
    ).toHaveLength(2);
  });
  it("rejects bundled react", () => {
    expect(inspectPackage({ ...good, outSources: { "package/out/x.js": "ReactCurrentOwner" } })).toHaveLength(1);
  });
  it("does not mistake the host-global shims for a bundled library", () => {
    const shim = {
      "package/out/renderer/_virtual/_global-external_react.js":
        "export const __SECRET_INTERNALS_DO_NOT_USE = global.React.x",
    };
    expect(inspectPackage({ ...good, outSources: shim })).toEqual([]);
  });
  it("rejects a missing entry file", () => {
    expect(inspectPackage({ ...good, files: ["package/package.json"] })).toHaveLength(2);
  });
});
