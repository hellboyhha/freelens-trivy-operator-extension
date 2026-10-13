// @vitest-environment jsdom

// Renders the list pages and the Overview with the synthetic fixtures, through the stub host.

import { Common } from "@freelensapp/extensions";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fixture } from "../../../test/fixtures";
import { testStores } from "../../../test/freelens-extensions";
import { ALL_REPORT_KINDS } from "../api/trivy";
import { resourceOf } from "../api/trivy/report-model";
import { CompliancePage } from "./compliance-page";
import { OverviewPage } from "./overview-page";
import { LISTS, MisconfigurationsPage, SbomsPage, SecretsPage, VulnerabilitiesPage } from "./report-list-pages";

import type { Renderer } from "@freelensapp/extensions";

const extension = { name: "@hellboyhha/freelens-trivy-operator-extension" } as Renderer.LensExtension;

const Kind = (name: string) => ALL_REPORT_KINDS.find((k) => k.kind.toLowerCase() === name.toLowerCase()) as any;

/** A loaded store holding the fixture of each kind named. */
function stockStores(...names: string[]) {
  for (const name of names) {
    const kind = Kind(name);
    testStores.set(kind, {
      isLoaded: true,
      failedLoading: false,
      loadAll: async () => {},
      contextItems: [new kind(fixture(name))],
      items: [new kind(fixture(name))],
    });
  }
}

beforeEach(() => {
  vi.mocked(Common.logger.error).mockClear();
  testStores.clear();
});
afterEach(() => {
  cleanup();
  expect(Common.logger.error, "a page fell back to the error page").not.toHaveBeenCalled();
});

const LIST_KINDS = Object.keys(LISTS) as (keyof typeof LISTS)[];

describe("list pages", () => {
  for (const name of LIST_KINDS) {
    it(`${name}: one cell per column, and the workload is named`, () => {
      stockStores(name);
      const Page = LISTS[name] as any;
      const { container } = render(<Page extension={extension} />);
      // A clean fixture is hidden by the "Hide Clean" chip that checks lists open with.
      const hideClean = screen.queryByRole("button", { name: "Hide Clean" });
      if (hideClean && screen.queryAllByTestId("cell").length === 0) fireEvent.click(hideClean);
      const headers = within(screen.getByTestId("header")).getAllByText(/.+/);
      const cells = screen.getAllByTestId("cell");
      expect(cells.length).toBe(headers.length);
      const ref = resourceOf(fixture(name).metadata);
      expect(ref.name, "the fixture names its workload").toBeTruthy();
      expect(container.textContent).toContain(ref.name);
    });
  }

  it("shows Critical, High, Medium and Low as their own columns, then fixable and scanned", () => {
    stockStores("vulnerabilityreport");
    const Page = LISTS.vulnerabilityreport as any;
    render(<Page extension={extension} />);
    const headers = within(screen.getByTestId("header"))
      .getAllByText(/.+/)
      .map((h) => h.textContent);
    expect(headers).toEqual(["Workload", "Image", "Critical", "High", "Medium", "Low", "Fixable", "Scanned"]);
    const cells = screen.getAllByTestId("cell");
    expect(cells.slice(2, 6).map((c) => c.textContent)).toEqual(["1", "1", "0", "1"]);
    expect(cells[2].querySelector("[aria-label]")?.getAttribute("aria-label")).toBe("1 critical");
    expect(cells[6].textContent).toBe("2");
    expect(cells[7].textContent).toMatch(/ago$/);
  });

  it("leaves the host header's title and item count out, since the page already says where you are", () => {
    stockStores("vulnerabilityreport");
    const Page = LISTS.vulnerabilityreport as any;
    render(<Page extension={extension} />);
    const host = screen.getByTestId("host-header").textContent;
    expect(host).not.toContain("host title");
    expect(host).not.toContain("host info");
  });

  it("keeps a report with only unknown-severity findings in the list, and shows no unknown label", () => {
    const kind = Kind("vulnerabilityreport");
    const base = fixture("vulnerabilityreport");
    const unknownOnly = new kind({
      ...base,
      report: { ...base.report, summary: { unknownCount: 20 }, vulnerabilities: [] },
    });
    testStores.set(kind, {
      isLoaded: true,
      failedLoading: false,
      loadAll: async () => {},
      contextItems: [unknownOnly],
      items: [unknownOnly],
    });
    const Page = LISTS.vulnerabilityreport as any;
    const { container } = render(<Page extension={extension} />);
    expect(container.textContent).not.toContain("no findings");
    expect(container.textContent).not.toContain("unknown");
    expect(screen.getAllByTestId("row")).toHaveLength(1);
  });

  it("names the worst failed check of a checks report", () => {
    stockStores("configauditreport");
    const Page = LISTS.configauditreport as any;
    const { container } = render(<Page extension={extension} />);
    expect(container.textContent).toContain("Root file system is not read-only");
    expect(container.textContent).toContain("+1 more");
  });

  it("lists baked-in secrets by rule without showing the matched text, and adds no banner", () => {
    stockStores("exposedsecretreport");
    const Page = LISTS.exposedsecretreport as any;
    const { container } = render(<Page extension={extension} />);
    expect(container.textContent).toContain("Asymmetric Private Key");
    expect(container.textContent).not.toContain("****");
    expect(container.textContent).not.toContain("Rotate each one");
    expect(screen.getByRole("button", { name: "Hide Clean" })).toBeTruthy();
  });

  it("turns the host's fixed-height virtual rows off so two-line cells fit", () => {
    stockStores("vulnerabilityreport");
    const Page = LISTS.vulnerabilityreport as any;
    const { container } = render(<Page extension={extension} />);
    expect(container.querySelector('[data-virtual="false"]')).not.toBeNull();
  });

  it("waits quietly for a store the host has dropped", () => {
    const Page = LISTS.vulnerabilityreport as any;
    const { container } = render(<Page extension={extension} />);
    expect(container.textContent).toContain("Waiting for");
  });
});

describe("accessibility of the toolbar controls", () => {
  it("chips announce whether they are on", () => {
    stockStores("vulnerabilityreport");
    const Page = LISTS.vulnerabilityreport as any;
    render(<Page extension={extension} />);
    expect(screen.getByRole("button", { name: "All" }).getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(screen.getByRole("button", { name: "Critical" }));
    expect(screen.getByRole("button", { name: "Critical" }).getAttribute("aria-pressed")).toBe("true");
    expect(screen.getByRole("button", { name: "All" }).getAttribute("aria-pressed")).toBe("false");
  });

  it("the scope switch is a group whose buttons announce the chosen scope", () => {
    stockStores("vulnerabilityreport", "clustervulnerabilityreport");
    render(<VulnerabilitiesPage extension={extension} />);
    expect(screen.getByRole("group", { name: "Scope" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Namespaced" }).getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(screen.getByRole("button", { name: "Cluster-Scoped" }));
    expect(screen.getByRole("button", { name: "Cluster-Scoped" }).getAttribute("aria-pressed")).toBe("true");
  });

  it("the Misconfigurations tabs are a tablist and mark the open one", () => {
    stockStores("configauditreport", "rbacassessmentreport", "infraassessmentreport");
    render(<MisconfigurationsPage extension={extension} />);
    expect(screen.getByRole("tablist")).toBeTruthy();
    const tabs = screen.getAllByRole("tab");
    expect(tabs).toHaveLength(3);
    expect(tabs[0].getAttribute("aria-selected")).toBe("true");
    fireEvent.click(tabs[1]);
    expect(screen.getAllByRole("tab")[1].getAttribute("aria-selected")).toBe("true");
  });
});

describe("filter chips", () => {
  /** Three vulnerability reports: critical+fixable, high only with no fix, and clean. */
  function stockMixed() {
    const kind = Kind("vulnerabilityreport");
    const make = (name: string, summary: object, vulnerabilities: object[]) => {
      const base = fixture("vulnerabilityreport");
      return new kind({
        ...base,
        metadata: {
          ...base.metadata,
          uid: name,
          name,
          labels: { ...base.metadata.labels, "trivy-operator.resource.name": name },
        },
        report: { ...base.report, summary, vulnerabilities },
      });
    };
    const items = [
      make("crit-fixable", { criticalCount: 1 }, [{ vulnerabilityID: "A", severity: "CRITICAL", fixedVersion: "2" }]),
      make("high-nofix", { highCount: 2 }, [{ vulnerabilityID: "B", severity: "HIGH", fixedVersion: "" }]),
      make("clean", {}, []),
    ];
    testStores.set(kind, { isLoaded: true, failedLoading: false, loadAll: async () => {}, contextItems: items, items });
  }
  const rows = (container: HTMLElement) =>
    [...container.querySelectorAll('[data-testid="row"]')].map((r) => r.textContent ?? "");
  const List = LISTS.vulnerabilityreport as any;

  it("shows every report until a chip is chosen, and All is lit", () => {
    stockMixed();
    const { container } = render(<List extension={extension} />);
    expect(rows(container)).toHaveLength(3);
  });

  it("Critical keeps reports with a critical finding, High those with a high one", () => {
    stockMixed();
    const { container } = render(<List extension={extension} />);
    fireEvent.click(screen.getByRole("button", { name: "Critical" }));
    expect(rows(container)).toHaveLength(1);
    expect(rows(container)[0]).toContain("crit-fixable");
    fireEvent.click(screen.getByRole("button", { name: "High" }));
    expect(rows(container)).toHaveLength(1);
    expect(rows(container)[0]).toContain("high-nofix");
    fireEvent.click(screen.getByRole("button", { name: "All" }));
    expect(rows(container)).toHaveLength(3);
  });

  it("Fixable Only and Hide Clean combine with a severity chip", () => {
    stockMixed();
    const { container } = render(<List extension={extension} />);
    fireEvent.click(screen.getByRole("button", { name: "Fixable Only" }));
    expect(rows(container)).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Fixable Only" }));
    fireEvent.click(screen.getByRole("button", { name: "Hide Clean" }));
    expect(rows(container)).toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name: "High" }));
    expect(rows(container)).toHaveLength(1);
  });

  it("the toolbar counts the reports, and how many are left once a chip is on", () => {
    stockMixed();
    render(<List extension={extension} />);
    expect(screen.getByTestId("count").textContent).toBe("3 reports");
    fireEvent.click(screen.getByRole("button", { name: "Hide Clean" }));
    expect(screen.getByTestId("count").textContent).toBe("2 of 3 reports");
    fireEvent.click(screen.getByRole("button", { name: "Critical" }));
    expect(screen.getByTestId("count").textContent).toBe("1 of 3 reports");
  });

  it("opens sorted by severity, worst first", () => {
    stockMixed();
    const { container } = render(<List extension={extension} />);
    expect(container.querySelector('[data-sort="critical"]')).not.toBeNull();
  });

  it("secrets open with Hide Clean already on", () => {
    stockStores("exposedsecretreport");
    const kind = Kind("exposedsecretreport");
    const base = fixture("exposedsecretreport");
    const clean = new kind({
      ...base,
      metadata: { ...base.metadata, uid: "clean", name: "clean-one" },
      report: { ...base.report, summary: {}, secrets: [] },
    });
    const store = testStores.get(kind) as any;
    store.contextItems = [...store.contextItems, clean];
    const Page = LISTS.exposedsecretreport as any;
    const { container } = render(<Page extension={extension} />);
    expect(rows(container)).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Hide Clean" }));
    expect(rows(container)).toHaveLength(2);
  });
});

describe("pages with a switch", () => {
  it("vulnerabilities: flips between namespaced and cluster-scoped reports", () => {
    stockStores("vulnerabilityreport", "clustervulnerabilityreport");
    const { container } = render(<VulnerabilitiesPage extension={extension} />);
    expect(screen.getByText("Namespaced")).toBeTruthy();
    expect(container.querySelectorAll('[data-testid="row"]').length).toBe(1);
    fireEvent.click(screen.getByText("Cluster-Scoped"));
    expect(container.querySelectorAll('[data-testid="row"]').length).toBe(1);
  });

  it("secrets: has no cluster-scoped switch because the operator has no such kind", () => {
    stockStores("exposedsecretreport");
    render(<SecretsPage extension={extension} />);
    expect(screen.queryByText("Cluster-Scoped")).toBeNull();
  });

  it("misconfigurations: three tabs with counts, and the scope switch", () => {
    stockStores("configauditreport", "rbacassessmentreport", "infraassessmentreport", "clusterconfigauditreport");
    const { container } = render(<MisconfigurationsPage extension={extension} />);
    expect(screen.getByText(/Config Audit/)).toBeTruthy();
    expect(screen.getByText(/RBAC/)).toBeTruthy();
    expect(screen.getByText(/Infrastructure/)).toBeTruthy();
    expect(container.textContent).toContain(resourceOf(fixture("configauditreport").metadata).name);
    fireEvent.click(screen.getByText(/RBAC/));
    expect(container.textContent).toContain(resourceOf(fixture("rbacassessmentreport").metadata).name);
    fireEvent.click(screen.getByText("Cluster-Scoped"));
    expect(container.textContent).not.toContain(resourceOf(fixture("rbacassessmentreport").metadata).name);
  });

  it("sbom: loads nothing until asked", () => {
    stockStores("sbomreport", "clustersbomreport");
    const { container } = render(<SbomsPage extension={extension} />);
    expect(container.querySelectorAll('[data-testid="row"]').length).toBe(0);
    // Plain, direct wording: what it is, why it waits, what you get.
    expect(container.textContent).toContain("SBOM reports load on request");
    expect(container.textContent).toContain("hundreds of megabytes");
    expect(container.textContent).toContain("search every report for a package");
    expect(container.textContent).not.toContain("They load only when you ask");
    fireEvent.click(screen.getByText("Load SBOMs"));
    expect(container.querySelectorAll('[data-testid="row"]').length).toBe(1);
    expect(container.textContent).toContain("demo/web:1.4.2");
  });
});

describe("SBOM package search", () => {
  const List = LISTS.sbomreport as any;
  const rows = (container: HTMLElement) => container.querySelectorAll('[data-testid="row"]').length;
  const search = (text: string) =>
    fireEvent.change(screen.getByPlaceholderText("Find a package"), { target: { value: text } });
  const hostHeader = () => within(screen.getByTestId("host-header"));

  it("puts the package box in the host header, next to the Search box", () => {
    stockStores("sbomreport");
    render(<List extension={extension} />);
    const box = hostHeader().getByPlaceholderText("Find a package");
    // The host's own SearchInput component, so it looks exactly like the Search box beside it.
    expect(box.getAttribute("data-host-component")).toBe("SearchInput");
    const hostSearch = screen.getByTestId("host-search");
    expect(box.parentElement).toBe(hostSearch.parentElement);
    expect(box.compareDocumentPosition(hostSearch) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("has no Matches column until something is typed", () => {
    stockStores("sbomreport");
    render(<List extension={extension} />);
    expect(within(screen.getByTestId("header")).queryByText("Matches")).toBeNull();
    search("libsample");
    expect(within(screen.getByTestId("header")).getByText("Matches")).toBeTruthy();
    search("");
    expect(within(screen.getByTestId("header")).queryByText("Matches")).toBeNull();
  });

  it("narrows the list to workloads that contain the package, and shows what matched", () => {
    stockStores("sbomreport");
    const { container } = render(<List extension={extension} />);
    search("libsample");
    expect(rows(container)).toBe(1);
    expect(container.textContent).toContain("libsample 2.3.0");
    expect(container.textContent).not.toContain("libexample 1.0.0");
    expect(screen.getByTestId("count").textContent).toBe("1 of 1 report");
  });

  it("matches the version and the purl too", () => {
    stockStores("sbomreport");
    const { container } = render(<List extension={extension} />);
    search("2.3.0");
    expect(rows(container)).toBe(1);
    search("pkg:deb/debian/libexample");
    expect(container.textContent).toContain("libexample 1.0.0");
  });

  it("shows no rows and says 0 of N when nothing contains the package", () => {
    stockStores("sbomreport");
    const { container } = render(<List extension={extension} />);
    search("no-such-package");
    expect(rows(container)).toBe(0);
    expect(screen.getByTestId("count").textContent).toBe("0 of 1 report");
  });

  it("words the host's Search box with the report's name in plain words", () => {
    stockStores("sbomreport", "vulnerabilityreport", "configauditreport", "clusterrbacassessmentreport");
    const placeholder = (name: keyof typeof LISTS) => {
      const Page = LISTS[name] as any;
      const view = render(<Page extension={extension} />);
      const text = screen.getByTestId("host-search").getAttribute("placeholder");
      view.unmount();
      return text;
    };
    expect(placeholder("sbomreport")).toBe("Search Sbom Report");
    expect(placeholder("vulnerabilityreport")).toBe("Search Vulnerability Report");
    expect(placeholder("configauditreport")).toBe("Search Config Audit Report");
    expect(placeholder("clusterrbacassessmentreport")).toBe("Search Cluster Rbac Assessment Report");
  });

  it("gives the Format column room and its own alignment, not the right-aligned number column's", () => {
    stockStores("sbomreport");
    render(<List extension={extension} />);
    const header = within(screen.getByTestId("header"));
    const format = header.getByText("Format").getAttribute("data-class");
    const components = header.getByText("Components").getAttribute("data-class");
    expect(format).toMatch(/format/);
    expect(format).not.toBe(components);
    expect(screen.getAllByTestId("cell").map((c) => c.textContent)).toContain("CycloneDX 1.6");
  });

  it("shows when each SBOM was generated", () => {
    stockStores("sbomreport");
    render(<List extension={extension} />);
    const headers = within(screen.getByTestId("header"))
      .getAllByText(/.+/)
      .map((h) => h.textContent);
    expect(headers).toContain("Scanned");
  });

  it("is only on the SBOM lists", () => {
    stockStores("vulnerabilityreport");
    const Page = LISTS.vulnerabilityreport as any;
    render(<Page extension={extension} />);
    expect(screen.queryByPlaceholderText("Find a package")).toBeNull();
  });
});

describe("Compliance", () => {
  it("shows a card per benchmark and its failing controls first", () => {
    stockStores("clustercompliancereport");
    const { container } = render(<CompliancePage extension={extension} />);
    const text = container.textContent ?? "";
    expect(text).toContain("Demo Benchmark v1.0");
    expect(text).toContain("passing");
    expect(text).toContain("First control");
  });

  it("filters controls by search and can show all of them", () => {
    stockStores("clustercompliancereport");
    const { container } = render(<CompliancePage extension={extension} />);
    fireEvent.click(screen.getByText("All controls"));
    expect(container.textContent).toContain("Second control");
    fireEvent.change(screen.getByPlaceholderText(/Search/), { target: { value: "first" } });
    expect(container.textContent).not.toContain("Second control");
    expect(container.textContent).toContain("First control");
  });

  it("explains when the operator has not written a report yet", () => {
    testStores.set(Kind("clustercompliancereport"), {
      isLoaded: true,
      loadAll: async () => {},
      contextItems: [],
      items: [],
    });
    const { container } = render(<CompliancePage extension={extension} />);
    expect(container.textContent).toContain("No compliance reports yet");
  });
});

describe("Overview", () => {
  const ALL = [
    "vulnerabilityreport",
    "clustervulnerabilityreport",
    "exposedsecretreport",
    "configauditreport",
    "clusterconfigauditreport",
    "rbacassessmentreport",
    "clusterrbacassessmentreport",
    "infraassessmentreport",
    "clusterinfraassessmentreport",
    "clustercompliancereport",
  ];

  it("leads with the critical count, then tiles, the fix-first list and the benchmarks", () => {
    stockStores(...ALL);
    const { container } = render(<OverviewPage extension={extension} />);
    const text = container.textContent ?? "";
    expect(text).toContain("2 critical");
    expect(text).toContain("2 have a fix");
    for (const tile of ["Vulnerabilities", "Exposed secrets", "Misconfigurations", "Compliance"])
      expect(text).toContain(tile);
    expect(text).toContain("Fix first");
    expect(text).toContain("demo/web:1.4.2");
    expect(text).toContain("Demo Benchmark v1.0");
  });

  it("titles the page bar Overview, as Freelens' own pages do", () => {
    stockStores(...ALL);
    const { container } = render(<OverviewPage extension={extension} />);
    const title = container.querySelector("h5");
    expect(title?.textContent).toBe("Overview");
    expect(container.textContent).not.toContain("Trivy Operator Overview");
  });

  it("lists the benchmarks in a table with failing and passing, and no progress bar", () => {
    stockStores(...ALL);
    const { container } = render(<OverviewPage extension={extension} />);
    const text = container.textContent ?? "";
    for (const head of ["Benchmark", "Failing", "Passing"]) expect(text).toContain(head);
    expect(text).toContain("Demo Benchmark v1.0");
    expect(text).not.toContain("Progress");
    expect(text).not.toContain("failing ·");
    // the only pass/fail bar left on the page is the one inside the Compliance tile
    const bars = [...container.querySelectorAll('[role="img"]')].map((e) => e.getAttribute("aria-label"));
    expect(bars.filter((label) => /^\d+ passing, \d+ failing$/.test(label ?? ""))).toHaveLength(1);
  });

  it("explains an empty selection and offers all namespaces", () => {
    testStores.set(Kind("vulnerabilityreport"), {
      isLoaded: true,
      loadAll: async () => {},
      contextItems: [],
      items: [],
    });
    const { container } = render(<OverviewPage extension={extension} />);
    expect(container.textContent).toContain("No Trivy Operator reports in the selected namespaces");
    fireEvent.click(screen.getByText("Show all namespaces"));
  });

  it("says a kind is not available instead of showing 0 when its reports cannot be read", () => {
    stockStores("vulnerabilityreport");
    const { container } = render(<OverviewPage extension={extension} />);
    const text = container.textContent ?? "";
    expect(text).toContain("Not available");
    expect(text).not.toContain("controls failing");
    expect(text).not.toMatch(/Exposed secrets0/);
    expect(text).toContain("Vulnerabilities");
  });

  it("names a failed load instead of blaming the namespace filter, and offers to retry", () => {
    const loadAll = vi.fn(async () => {});
    testStores.set(Kind("vulnerabilityreport"), {
      isLoaded: false,
      failedLoading: true,
      loadAll,
      contextItems: [],
      items: [],
    });
    const { container } = render(<OverviewPage extension={extension} />);
    expect(container.textContent).toContain("Could not load Trivy Operator reports");
    expect(container.textContent).not.toContain("No Trivy Operator reports in the selected namespaces");
    loadAll.mockClear();
    fireEvent.click(screen.getByText("Try again"));
    expect(loadAll).toHaveBeenCalled();
  });

  it("counts an image once, and uses singular words for one", () => {
    const kind = Kind("vulnerabilityreport");
    const base = fixture("vulnerabilityreport");
    const copy = (uid: string) =>
      new kind({
        ...base,
        metadata: { ...base.metadata, uid, name: uid },
        report: {
          ...base.report,
          summary: { criticalCount: 1 },
          vulnerabilities: [{ vulnerabilityID: "A", severity: "CRITICAL", fixedVersion: "2" }],
        },
      });
    const items = [copy("a"), copy("b"), copy("c")];
    testStores.set(kind, { isLoaded: true, failedLoading: false, loadAll: async () => {}, contextItems: items, items });
    const { container } = render(<OverviewPage extension={extension} />);
    expect(container.textContent).toContain("3 critical vulnerabilities across 1 image");
    cleanup();
    testStores.set(kind, {
      isLoaded: true,
      failedLoading: false,
      loadAll: async () => {},
      contextItems: [items[0]],
      items: [items[0]],
    });
    const one = render(<OverviewPage extension={extension} />);
    expect(one.container.textContent).toContain("1 critical vulnerability across 1 image");
    expect(one.container.textContent).toContain("1 has a fix");
  });

  it("shows the Fix first table with a column per severity and no abbreviations", () => {
    stockStores("vulnerabilityreport");
    const { container } = render(<OverviewPage extension={extension} />);
    const text = container.textContent ?? "";
    for (const head of ["Critical", "High", "Medium", "Low"]) expect(text).toContain(head);
    expect(text).not.toContain("Severity");
    expect(text).not.toContain("Crit ");
    expect(container.querySelector('[aria-label="1 critical"]')).not.toBeNull();
  });

  it("says how many sources a tile lacks when only some are available", () => {
    stockStores("vulnerabilityreport", "configauditreport");
    const { container } = render(<OverviewPage extension={extension} />);
    expect(container.textContent).toContain("5 of 6 sources not available");
  });

  it("shows placeholders while the first store loads", () => {
    testStores.set(Kind("vulnerabilityreport"), {
      isLoaded: false,
      failedLoading: false,
      loadAll: async () => {},
      contextItems: [],
      items: [],
    });
    const { container } = render(<OverviewPage extension={extension} />);
    expect(container.textContent).not.toContain("No Trivy Operator reports");
  });
});
