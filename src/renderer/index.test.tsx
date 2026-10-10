// @vitest-environment jsdom

import { Common } from "@freelensapp/extensions";
import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { fixture } from "../../test/fixtures";
import { testStores } from "../../test/freelens-extensions";
import { ALL_REPORT_KINDS } from "./api/trivy";
import TrivyOperatorRenderer from "./index";
import { extensionPageUrl } from "./navigation";

// The extension is wired by ids: a menu entry that points at a page nobody registered, or at a
// parent that does not exist, is an entry that silently fails to appear in Freelens.
describe("extension wiring", () => {
  const extension = new TrivyOperatorRenderer({} as never) as unknown as {
    clusterPages: { id: string; components: { Page: unknown } }[];
    clusterPageMenus: { id: string; parentId?: string; title: string; target: { pageId: string } }[];
    kubeObjectDetailItems: { kind: string; apiVersions: string[]; components: { Details: unknown } }[];
  };
  const pageIds = extension.clusterPages.map((p) => p.id);
  const menuIds = extension.clusterPageMenus.map((m) => m.id);

  it("registers each page once, with a component", () => {
    expect(new Set(pageIds).size).toBe(pageIds.length);
    for (const page of extension.clusterPages) expect(typeof page.components.Page).toBe("function");
  });

  it("gives each menu entry a unique id", () => {
    expect(new Set(menuIds).size).toBe(menuIds.length);
  });

  it("points every menu entry at a registered page", () => {
    for (const menu of extension.clusterPageMenus) expect(pageIds, menu.id).toContain(menu.target.pageId);
  });

  it("hangs every group and page under an existing parent", () => {
    for (const menu of extension.clusterPageMenus) {
      if (menu.parentId) expect(menuIds, menu.id).toContain(menu.parentId);
    }
    expect(extension.clusterPageMenus.filter((m) => !m.parentId).map((m) => m.title)).toEqual(["Trivy Operator"]);
  });

  it("keeps the sidebar to the root and six pages", () => {
    expect(extension.clusterPageMenus.map((m) => m.title)).toEqual([
      "Trivy Operator",
      "Overview",
      "Vulnerabilities",
      "Misconfigurations",
      "Secrets",
      "SBOM",
      "Compliance",
    ]);
  });

  it("opens the Overview from the root entry", () => {
    expect(extension.clusterPageMenus[0].target.pageId).toBe("trivy-overview");
  });

  it("adds a drawer section to every report kind and to the workload kinds", () => {
    const kinds = extension.kubeObjectDetailItems.map((d) => d.kind);
    for (const kind of [
      "VulnerabilityReport",
      "ClusterComplianceReport",
      "SbomReport",
      "ConfigAuditReport",
      "Pod",
      "Deployment",
      "CronJob",
    ]) {
      expect(kinds).toContain(kind);
    }
    for (const item of extension.kubeObjectDetailItems) {
      expect(item.apiVersions.length).toBeGreaterThan(0);
      expect(typeof item.components.Details).toBe("function");
    }
  });

  it("builds page URLs from the package name", () => {
    expect(extensionPageUrl(new TrivyOperatorRenderer({} as never).name, "trivy-overview")).toBe(
      "/extension/hellboyhha--freelens-trivy-operator-extension/trivy-overview",
    );
  });
});

// Freelens renders a cluster page as `<Page />`, with no props. A page that needs the extension
// must get it from the registration; one that reads it from props crashes the moment anything
// goes wrong, because the error page needs it too.
describe("pages as the host renders them", () => {
  afterEach(() => {
    cleanup();
    testStores.clear();
  });

  it("render with every store loaded, without props and without an error", () => {
    for (const Kind of ALL_REPORT_KINDS) {
      const object = new (Kind as any)(fixture(Kind.kind));
      testStores.set(Kind, {
        isLoaded: true,
        failedLoading: false,
        loadAll: async () => {},
        contextItems: [object],
        items: [object],
      });
    }
    const extension = new TrivyOperatorRenderer({} as never) as unknown as {
      clusterPages: { id: string; components: { Page: () => JSX.Element } }[];
    };
    vi.mocked(Common.logger.error).mockClear();
    for (const page of extension.clusterPages) {
      const { container } = render(<page.components.Page />);
      expect(container.textContent, page.id).not.toBe("");
      expect(container.textContent, page.id).not.toContain("not installed");
      cleanup();
    }
    expect(Common.logger.error).not.toHaveBeenCalled();
  });

  it("explain a missing operator instead of failing", () => {
    const extension = new TrivyOperatorRenderer({} as never) as unknown as {
      clusterPages: { id: string; components: { Page: () => JSX.Element } }[];
    };
    for (const page of extension.clusterPages) {
      const { container } = render(<page.components.Page />);
      expect(container.textContent, page.id).toContain("Trivy Operator is not installed");
      cleanup();
    }
  });
});
