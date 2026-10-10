// @vitest-environment jsdom

// Exporting what a list shows, through the stub host.

import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fixture } from "../../../test/fixtures";
import { activeCluster, notifications, testStores } from "../../../test/freelens-extensions";
import { selectableStore } from "../../../test/stores";
import { ALL_REPORT_KINDS } from "../api/trivy";
import { LISTS } from "./report-list-pages";

import type { Renderer } from "@freelensapp/extensions";

const extension = { name: "@hellboyhha/freelens-trivy-operator-extension" } as Renderer.LensExtension;
const Kind = (name: string) => (ALL_REPORT_KINDS as unknown as any[]).find((k) => k.kind.toLowerCase() === name) as any;
const Page = (name: string) => LISTS[name as keyof typeof LISTS] as any;

/** Three reports: alpha critical, beta high, gamma clean. */
function stock(kindName = "vulnerabilityreport") {
  const kind = Kind(kindName);
  const base = fixture(kindName);
  const make = (name: string, summary: object) =>
    new kind({
      ...base,
      metadata: {
        ...base.metadata,
        uid: name,
        name,
        labels: { ...base.metadata.labels, "trivy-operator.resource.name": name },
      },
      report: { ...base.report, summary: { ...base.report.summary, ...summary } },
    });
  const objects = [
    make("alpha", { criticalCount: 1 }),
    make("beta", { criticalCount: 0, highCount: 2 }),
    make("gamma", { criticalCount: 0, highCount: 0 }),
  ];
  testStores.set(kind, selectableStore(objects));
  return objects;
}

/** Captures what the page offers as a download. */
function captureDownloads() {
  const saved: { name: string; blob: Blob }[] = [];
  let blob: Blob | undefined;
  URL.createObjectURL = vi.fn((b: Blob) => {
    blob = b;
    return "blob:test";
  });
  URL.revokeObjectURL = vi.fn();
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
    saved.push({ name: this.download, blob: blob as Blob });
  });
  return saved;
}

const textOf = (blob: Blob) =>
  new Promise<string>((resolve) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.readAsText(blob);
  });

const ticks = () => screen.getAllByTestId("select") as HTMLInputElement[];
const tick = (...indexes: number[]) => indexes.forEach((i) => fireEvent.click(ticks()[i]));
const exportButton = () => screen.getByRole("button", { name: /^Export/ }) as HTMLButtonElement;
const openMenu = () => fireEvent.click(exportButton());
const choose = (name: RegExp) => fireEvent.click(screen.getByRole("menuitem", { name }));

beforeEach(() => {
  testStores.clear();
  activeCluster.name = "test-cluster";
  for (const fn of Object.values(notifications)) fn.mockClear();
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("the Export button", () => {
  it("is there before anything is ticked, disabled like Rescan", () => {
    stock();
    const P = Page("vulnerabilityreport");
    render(<P extension={extension} />);
    expect(exportButton().disabled).toBe(true);
    expect(screen.getAllByTitle("Tick workloads to rescan or export")).toHaveLength(2);
    fireEvent.click(exportButton());
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("turns on with the first tick and says how many it will export", () => {
    stock();
    const P = Page("vulnerabilityreport");
    render(<P extension={extension} />);
    tick(0);
    expect(exportButton().disabled).toBe(false);
    expect(exportButton().textContent).toContain("Export 1");
    tick(1);
    expect(exportButton().textContent).toContain("Export 2");
  });

  it("turns off again when the ticks are cleared", () => {
    stock();
    const P = Page("vulnerabilityreport");
    render(<P extension={extension} />);
    tick(0);
    fireEvent.click(screen.getByRole("button", { name: "Clear" }));
    expect(exportButton().disabled).toBe(true);
  });
});

describe("the Export menu", () => {
  it("names what it exports, then offers reports, findings and JSON", () => {
    stock();
    const P = Page("vulnerabilityreport");
    render(<P extension={extension} />);
    tick(0, 1);
    expect(screen.queryByRole("menu")).toBeNull();
    openMenu();
    const menu = within(screen.getByRole("menu"));
    expect(menu.getByText("2 ticked workloads")).toBeTruthy();
    expect(menu.getByRole("menuitem", { name: /Reports.*CSV/ })).toBeTruthy();
    expect(menu.getByRole("menuitem", { name: /Findings.*CSV/ })).toBeTruthy();
    expect(menu.getByRole("menuitem", { name: /JSON/ })).toBeTruthy();
  });

  it("says workload, not workloads, for one", () => {
    stock();
    const P = Page("vulnerabilityreport");
    render(<P extension={extension} />);
    tick(0);
    openMenu();
    expect(screen.getByText("1 ticked workload")).toBeTruthy();
  });

  it("leaves out findings for SBOMs, whose reports list components", () => {
    stock("sbomreport");
    const P = Page("sbomreport");
    render(<P extension={extension} />);
    tick(0);
    openMenu();
    expect(screen.queryByRole("menuitem", { name: /Findings/ })).toBeNull();
    expect(screen.getByRole("menuitem", { name: /Reports.*CSV/ })).toBeTruthy();
  });

  it("closes with Escape and after a choice", () => {
    stock();
    captureDownloads();
    const P = Page("vulnerabilityreport");
    render(<P extension={extension} />);
    tick(0);
    openMenu();
    fireEvent.keyDown(screen.getByRole("menu"), { key: "Escape" });
    expect(screen.queryByRole("menu")).toBeNull();
    openMenu();
    choose(/Reports.*CSV/);
    expect(screen.queryByRole("menu")).toBeNull();
  });
});

describe("what is exported", () => {
  it("downloads one row per ticked report, named for the list, cluster and day", async () => {
    stock();
    const saved = captureDownloads();
    const P = Page("vulnerabilityreport");
    render(<P extension={extension} />);
    tick(0, 2);
    openMenu();
    choose(/Reports.*CSV/);
    expect(saved).toHaveLength(1);
    expect(saved[0].name).toMatch(/^trivy-vulnerabilities-test-cluster-\d{8}\.csv$/);
    const lines = (await textOf(saved[0].blob)).trim().split("\r\n");
    expect(lines).toHaveLength(3);
    expect(lines.join("\n")).toContain("alpha");
    expect(lines.join("\n")).toContain("gamma");
    expect(lines.join("\n")).not.toContain("beta");
    await waitFor(() => expect(notifications.ok).toHaveBeenCalled());
    expect(String(notifications.ok.mock.calls[0][0])).toContain("Exported 2 reports");
  });

  it("keeps the ticks after exporting, so another format is one click away", () => {
    stock();
    captureDownloads();
    const P = Page("vulnerabilityreport");
    render(<P extension={extension} />);
    tick(0);
    openMenu();
    choose(/Reports.*CSV/);
    expect(exportButton().textContent).toContain("Export 1");
    expect(ticks()[0].checked).toBe(true);
  });

  it("does not export a ticked report that a chip hides", async () => {
    stock();
    const saved = captureDownloads();
    const P = Page("vulnerabilityreport");
    render(<P extension={extension} />);
    tick(0, 1);
    fireEvent.click(screen.getByRole("button", { name: "Critical" }));
    await waitFor(() => expect(exportButton().textContent).toContain("Export 1"));
    openMenu();
    choose(/Reports.*CSV/);
    const lines = (await textOf(saved[0].blob)).trim().split("\r\n");
    expect(lines).toHaveLength(2);
    expect(lines[1]).toContain("alpha");
    expect(String(notifications.ok.mock.calls[0][0])).toContain("Exported 1 report ");
  });

  it("writes findings as one row per CVE of the ticked reports", async () => {
    stock();
    const saved = captureDownloads();
    const P = Page("vulnerabilityreport");
    render(<P extension={extension} />);
    tick(0, 1);
    openMenu();
    choose(/Findings.*CSV/);
    expect(saved[0].name).toContain("-findings-");
    const lines = (await textOf(saved[0].blob)).trim().split("\r\n");
    expect(lines).toHaveLength(1 + 2 * 3);
    expect(lines.join("\n")).toContain("CVE-2099-0001");
  });

  it("writes JSON with the cluster and the ticked reports", async () => {
    stock();
    const saved = captureDownloads();
    const P = Page("vulnerabilityreport");
    render(<P extension={extension} />);
    tick(1);
    openMenu();
    choose(/JSON/);
    expect(saved[0].name).toMatch(/\.json$/);
    const data = JSON.parse(await textOf(saved[0].blob));
    expect(data).toMatchObject({ cluster: "test-cluster", count: 1 });
  });
});
