import { describe, expect, it } from "vitest";
import { checkArchitecture } from "./architecture.mjs";

const run = (path, text, options) => checkArchitecture([{ path, text }], options).map((v) => v.rule);

describe("layer-direction", () => {
  it("rejects renderer importing main", () => {
    expect(run("src/renderer/index.tsx", `import { x } from "../main/x";`)).toEqual(["layer-direction"]);
  });
  it("rejects main importing renderer", () => {
    expect(run("src/main/index.ts", `import { x } from "../renderer/x";`)).toEqual(["layer-direction"]);
  });
  it("rejects common importing renderer", () => {
    expect(run("src/common/a.ts", `export * from "../renderer/x";`)).toEqual(["layer-direction"]);
  });
  it("allows renderer importing common and itself", () => {
    expect(
      run(
        "src/renderer/pages/a.tsx",
        `import { x } from "../../common/x";\nimport { y } from "../components/y";\nwithErrorPage();`,
      ),
    ).toEqual([]);
  });
});

describe("kubeobject rules", () => {
  const shape = `static readonly kind = "X"; static readonly namespaced = true; static readonly apiBase = "/a"; static readonly crd = {};`;
  it("rejects instance methods and accessors", () => {
    const src = `class X extends Renderer.K8sApi.LensExtensionKubeObject { ${shape} getThing() { return 1; } get foo() { return 1; } }`;
    expect(run("src/renderer/api/x.ts", src)).toEqual(["kubeobject-static-only", "kubeobject-static-only"]);
  });
  it("allows static methods and declared fields", () => {
    const src = `class X extends Renderer.K8sApi.LensExtensionKubeObject { ${shape} report?: object; static getThing(o: X) { return o; } }`;
    expect(run("src/renderer/api/x.ts", src)).toEqual([]);
  });
  it("requires the static shape", () => {
    const src = `class X extends Renderer.K8sApi.LensExtensionKubeObject { static readonly kind = "X"; }`;
    expect(run("src/renderer/api/x.ts", src)).toEqual(["kubeobject-shape", "kubeobject-shape", "kubeobject-shape"]);
  });
  it("ignores unrelated classes", () => {
    expect(run("src/renderer/a.ts", `class A { foo() {} }`)).toEqual([]);
  });
});

describe("read-only-gate", () => {
  const RESCAN = "src/renderer/api/trivy/rescan.ts";

  it("rejects writes through a store", () => {
    expect(run("src/renderer/menus/a.tsx", `await Foo.getStore().patch(o, {}, "merge");`)).toEqual(["read-only-gate"]);
    expect(run("src/renderer/menus/a.tsx", `await this.api.delete(o);`)).toEqual(["read-only-gate"]);
  });
  it("rejects the store's own remove methods, which delete from the cluster", () => {
    for (const call of [
      "store.remove(o)",
      "store.removeItems(list)",
      "store.removeSelectedItems()",
      "store.removeWithOptions(o, {})",
    ]) {
      expect(run("src/renderer/components/a.ts", `${call};`), call).toEqual(["read-only-gate"]);
    }
  });
  it("ignores unrelated delete/create/remove calls", () => {
    expect(run("src/renderer/a.ts", `map.delete(k); Object.create(null); list.remove(x);`)).toEqual([]);
  });
  it("allows writes in the one module that rescans, and nowhere else", () => {
    expect(run(RESCAN, `await store.remove(o);`)).toEqual([]);
    expect(run("src/renderer/components/report-list.tsx", `await store.remove(o);`)).toEqual(["read-only-gate"]);
    expect(run("src/renderer/api/trivy/other.ts", `await store.remove(o);`)).toEqual(["read-only-gate"]);
  });
  it("names the allowed module in the message", () => {
    const [violation] = checkArchitecture([{ path: "src/renderer/a.ts", text: "store.patch(o, {});" }]);
    expect(violation.message).toContain("rescan.ts");
  });
  it("can be lifted deliberately", () => {
    expect(run("src/renderer/a.ts", `store.patch(o, {});`, { allowWrites: true })).toEqual([]);
  });
});

describe("page-error-boundary", () => {
  it("requires withErrorPage in pages", () => {
    expect(run("src/renderer/pages/a.tsx", `export const A = () => null;`)).toEqual(["page-error-boundary"]);
  });
  it("accepts a page that uses it", () => {
    expect(run("src/renderer/pages/a.tsx", `export const A = (p) => withErrorPage(p, () => null);`)).toEqual([]);
  });
  it("accepts a page built by the list factory", () => {
    expect(run("src/renderer/pages/a.tsx", `export const A = createReportListPage({});`)).toEqual([]);
  });
  it("does not require it for tests", () => {
    expect(run("src/renderer/pages/a.test.tsx", `it("x", () => {});`)).toEqual([]);
  });
});
