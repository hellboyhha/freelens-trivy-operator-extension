// @vitest-environment jsdom

// Selecting reports and rescanning them, through the stub host.

import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { runInAction } from "mobx";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { fixture } from "../../../test/fixtures";
import { activeCluster, notifications, scanApi, testStores } from "../../../test/freelens-extensions";
import { selectableStore } from "../../../test/stores";
import { ALL_REPORT_KINDS } from "../api/trivy";
import { STALE_AFTER_MS } from "../api/trivy/rescan-model";
import { rescanTracker } from "../api/trivy/rescan-tracker";
import { CompliancePage } from "./compliance-page";
import { LISTS } from "./report-list-pages";

import type { Renderer } from "@freelensapp/extensions";

const extension = { name: "@hellboyhha/freelens-trivy-operator-extension" } as Renderer.LensExtension;
const Kind = (name: string) => (ALL_REPORT_KINDS as unknown as any[]).find((k) => k.kind.toLowerCase() === name) as any;

/** Three vulnerability reports in two namespaces. */
function stock(kindName = "vulnerabilityreport") {
  const kind = Kind(kindName);
  const base = fixture(kindName);
  const make = (name: string, namespace: string, summary: object) =>
    new kind({
      ...base,
      metadata: {
        ...base.metadata,
        uid: `${name}-1`,
        name,
        namespace,
        labels: {
          ...base.metadata.labels,
          "trivy-operator.resource.name": name,
          "trivy-operator.resource.namespace": namespace,
        },
      },
      report: { ...base.report, summary, vulnerabilities: [] },
    });
  const objects = [
    make("alpha", "demo", { criticalCount: 1 }),
    make("beta", "demo", { highCount: 2 }),
    make("gamma", "ops", {}),
  ];
  const store = selectableStore(objects);
  testStores.set(kind, store);
  return { kind, store, objects, make };
}

const Page = (kindName = "vulnerabilityreport") => LISTS[kindName as keyof typeof LISTS] as any;
const ticks = () => screen.getAllByTestId("select") as HTMLInputElement[];
const rows = () => screen.queryAllByTestId("row");
const click = (name: string | RegExp) => fireEvent.click(screen.getByRole("button", { name }));

beforeEach(() => {
  scanApi.jobs = [];
  scanApi.pods = [];
  scanApi.fail = false;
  testStores.clear();
  rescanTracker.list().forEach((p) => rescanTracker.dismiss(p.key));
  for (const fn of Object.values(notifications)) fn.mockClear();
  activeCluster.name = "test-cluster";
});
afterEach(cleanup);

describe("the toolbar actions", () => {
  const toolbarRescan = () => screen.getByRole("button", { name: /^Rescan( \d+)?$/ }) as HTMLButtonElement;

  it("shows Rescan before anything is ticked, disabled, with the reason", () => {
    stock();
    const P = Page();
    render(<P extension={extension} />);
    expect(toolbarRescan().disabled).toBe(true);
    expect(toolbarRescan().textContent).toContain("Rescan");
    expect(screen.getAllByTitle("Tick workloads to rescan or export")).toHaveLength(2);
    expect(screen.queryByText(/selected/)).toBeNull();
  });

  it("does nothing when a disabled Rescan is clicked", () => {
    const { store } = stock();
    const P = Page();
    render(<P extension={extension} />);
    fireEvent.click(toolbarRescan());
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(store.remove).not.toHaveBeenCalled();
  });

  it("turns on with the first tick and counts the selection next to the report count", () => {
    stock();
    const P = Page();
    render(<P extension={extension} />);
    fireEvent.click(ticks()[0]);
    expect(toolbarRescan().disabled).toBe(false);
    expect(toolbarRescan().textContent).toContain("Rescan 1");
    expect(screen.getByTestId("count").textContent).toBe("3 reports · 1 selected Clear");
    fireEvent.click(ticks()[1]);
    expect(toolbarRescan().textContent).toContain("Rescan 2");
    expect(screen.getByTestId("count").textContent).toBe("3 reports · 2 selected Clear");
  });

  it("has no separate selection bar above the list", () => {
    stock();
    const P = Page();
    render(<P extension={extension} />);
    fireEvent.click(ticks()[0]);
    expect(screen.queryByRole("region", { name: "Selection" })).toBeNull();
  });

  it("Clear unticks everything and turns Rescan off again", () => {
    stock();
    const P = Page();
    render(<P extension={extension} />);
    fireEvent.click(ticks()[0]);
    fireEvent.click(ticks()[1]);
    click("Clear");
    expect(ticks().every((t) => !t.checked)).toBe(true);
    expect(toolbarRescan().disabled).toBe(true);
    expect(screen.queryByText(/selected/)).toBeNull();
  });

  it("counts only the reports the filters leave visible", async () => {
    stock();
    const P = Page();
    render(<P extension={extension} />);
    fireEvent.click(ticks()[0]);
    fireEvent.click(ticks()[1]);
    expect(toolbarRescan().textContent).toContain("Rescan 2");
    click("Critical");
    // The toolbar learns of the table's new rows one beat after the click.
    await waitFor(() => expect(toolbarRescan().textContent).toContain("Rescan 1"));
  });

  it("replaces the host's own remove button, so there is one deliberate way to delete", () => {
    stock();
    const P = Page();
    const { container } = render(<P extension={extension} />);
    expect(container.querySelector('[data-host-remove="false"]')).not.toBeNull();
  });

  it("is on every report list, but not on Compliance or SBOM", () => {
    for (const name of ["exposedsecretreport", "configauditreport"]) {
      cleanup();
      testStores.clear();
      stock(name);
      const P = Page(name);
      render(<P extension={extension} />);
      expect(screen.getAllByTestId("select").length, name).toBeGreaterThan(0);
    }

    // SBOM: the operator does not regenerate a deleted SBOM report, so Rescan must not be offered.
    cleanup();
    testStores.clear();
    stock("sbomreport");
    const SbomPage = Page("sbomreport");
    render(<SbomPage extension={extension} />);
    expect(screen.queryByRole("button", { name: /^Rescan/ })).toBeNull();
    expect(screen.getByRole("button", { name: /^Export/ })).toBeTruthy();

    cleanup();
    testStores.set(
      Kind("clustercompliancereport"),
      selectableStore([new (Kind("clustercompliancereport"))(fixture("clustercompliancereport"))]),
    );
    render(<CompliancePage extension={extension} />);
    expect(screen.queryByText(/Rescan/)).toBeNull();
  });
});

describe("rescanning one report", () => {
  it("asks first, naming the cluster, the workload and the image", () => {
    const { store } = stock();
    const P = Page();
    render(<P extension={extension} />);
    fireEvent.click(ticks()[0]);
    click("Rescan 1");
    const dialog = within(screen.getByRole("dialog"));
    expect(dialog.getByText("Rescan this workload?")).toBeTruthy();
    // The cluster is named in plain text, not in a highlighted chip.
    expect(dialog.getByText("test-cluster").tagName).toBe("DD");
    expect(dialog.getByText(/alpha/)).toBeTruthy();
    expect(dialog.getByText("demo/web:1.4.2")).toBeTruthy();
    expect(dialog.queryByRole("textbox")).toBeNull();
    expect(store.remove).not.toHaveBeenCalled();
  });

  it("Cancel and Escape close it without changing anything", () => {
    const { store } = stock();
    const P = Page();
    render(<P extension={extension} />);
    fireEvent.click(ticks()[0]);
    click("Rescan 1");
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    click("Rescan 1");
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(store.remove).not.toHaveBeenCalled();
  });

  it("deletes the report on confirm, tells the user, and clears the selection", async () => {
    const { store, objects } = stock();
    const P = Page();
    render(<P extension={extension} />);
    fireEvent.click(ticks()[0]);
    click("Rescan 1");
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Rescan" }));
    await waitFor(() => expect(store.remove).toHaveBeenCalledWith(objects[0]));
    await waitFor(() => expect(notifications.ok).toHaveBeenCalledTimes(1));
    expect(String(notifications.ok.mock.calls[0][0])).toContain("Rescan requested for 1 workload");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.queryByRole("region", { name: "Selection" })).toBeNull();
  });
});

describe("rescanning several reports", () => {
  it("makes the user type the cluster name before the button works", async () => {
    const { store } = stock();
    const P = Page();
    render(<P extension={extension} />);
    fireEvent.click(ticks()[0]);
    fireEvent.click(ticks()[1]);
    click("Rescan 2");
    const dialog = within(screen.getByRole("dialog"));
    expect(dialog.getByText("Rescan 2 workloads?")).toBeTruthy();
    expect(dialog.getByText("demo")).toBeTruthy();
    const confirm = dialog.getByRole("button", { name: "Rescan 2" }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    fireEvent.change(dialog.getByRole("textbox"), { target: { value: "test-clust" } });
    expect(confirm.disabled).toBe(true);
    fireEvent.change(dialog.getByRole("textbox"), { target: { value: "test-cluster" } });
    expect(confirm.disabled).toBe(false);
    fireEvent.click(confirm);
    await waitFor(() => expect(store.remove).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(notifications.ok).toHaveBeenCalled());
    expect(String(notifications.ok.mock.calls[0][0])).toContain("2 workloads");
  });

  it("asks for the word rescan when the cluster has no name", () => {
    activeCluster.name = "";
    stock();
    const P = Page();
    render(<P extension={extension} />);
    fireEvent.click(ticks()[0]);
    fireEvent.click(ticks()[1]);
    click("Rescan 2");
    const dialog = within(screen.getByRole("dialog"));
    fireEvent.change(dialog.getByRole("textbox"), { target: { value: "rescan" } });
    expect((dialog.getByRole("button", { name: "Rescan 2" }) as HTMLButtonElement).disabled).toBe(false);
  });

  it("names the namespaces, each once", () => {
    stock();
    const P = Page();
    render(<P extension={extension} />);
    for (const tick of ticks()) fireEvent.click(tick);
    click("Rescan 3");
    expect(within(screen.getByRole("dialog")).getByText("demo, ops")).toBeTruthy();
  });
});

describe("while the operator scans again", () => {
  async function requestRescan(count = 1) {
    const ctx = stock();
    const P = Page();
    const view = render(<P extension={extension} />);
    for (let i = 0; i < count; i++) fireEvent.click(ticks()[i]);
    click(`Rescan ${count}`);
    const dialog = within(screen.getByRole("dialog"));
    if (count > 1) fireEvent.change(dialog.getByRole("textbox"), { target: { value: "test-cluster" } });
    fireEvent.click(dialog.getByRole("button", { name: count > 1 ? `Rescan ${count}` : "Rescan" }));
    await waitFor(() => expect(ctx.store.remove).toHaveBeenCalledTimes(count));
    await waitFor(() => expect(notifications.ok).toHaveBeenCalled());
    return { ...ctx, view };
  }

  it("keeps the report as a Rescanning row instead of letting it vanish", async () => {
    await requestRescan();
    expect(rows()).toHaveLength(3);
    const ghost = rows().find((r) => r.textContent?.includes("alpha"))!;
    expect(ghost.textContent).toContain("Queued");
    expect(ghost.textContent).toMatch(/<1m/);
    expect(rows().filter((r) => r.textContent?.includes("Queued"))).toHaveLength(1);
  });

  it("says how many are rescanning next to the count", async () => {
    await requestRescan();
    expect(screen.getByTestId("count").textContent).toBe("2 reports · 1 rescanning");
  });

  it("does not open a drawer when the waiting row is clicked", async () => {
    await requestRescan();
    const ghost = rows().find((r) => r.textContent?.includes("Queued"))!;
    expect(ghost.getAttribute("data-row-click-overridden")).toBe("true");
    const normal = rows().find((r) => !r.textContent?.includes("Queued"))!;
    expect(normal.getAttribute("data-row-click-overridden")).toBe("false");
  });

  it("turns the row back into a report when the operator writes the new one", async () => {
    const { store, make } = await requestRescan();
    runInAction(() => {
      const fresh = make("alpha", "demo", { criticalCount: 1 });
      fresh.metadata.uid = "alpha-2";
      store.items.push(fresh);
    });
    await waitFor(() => expect(screen.queryByText(/Rescanning/)).toBeNull());
    expect(rows()).toHaveLength(3);
    expect(screen.getByTestId("count").textContent).toBe("3 reports");
    expect(rescanTracker.list()).toEqual([]);
  });

  it("says so when no new report has appeared after ten minutes", async () => {
    await requestRescan();
    const entry = rescanTracker.list()[0];
    runInAction(() => {
      entry.requestedAt = Date.now() - STALE_AFTER_MS - 1000;
    });
    cleanup();
    const P = Page();
    render(<P extension={extension} />);
    expect(screen.getByText("No new report after 10m")).toBeTruthy();
  });

  it("applies the chips to a waiting row like to any other", async () => {
    await requestRescan();
    click("High");
    expect(rows().some((r) => r.textContent?.includes("Queued"))).toBe(false);
  });
});

describe("when the cluster says no", () => {
  it("explains a forbidden answer and leaves the report where it was", async () => {
    const { store } = stock();
    store.remove.mockRejectedValueOnce(new Error('vulnerabilityreports "alpha" is forbidden: cannot delete'));
    const P = Page();
    render(<P extension={extension} />);
    fireEvent.click(ticks()[0]);
    click("Rescan 1");
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Rescan" }));
    await waitFor(() => expect(notifications.error).toHaveBeenCalled());
    expect(String(notifications.error.mock.calls[0][0])).toContain("Forbidden");
    expect(notifications.ok).not.toHaveBeenCalled();
    expect(screen.queryByText(/Rescanning/)).toBeNull();
    expect(rows()).toHaveLength(3);
  });

  it("says nothing was changed when the report was already gone", async () => {
    const { store } = stock();
    store.remove.mockRejectedValueOnce({ code: 404 });
    const P = Page();
    render(<P extension={extension} />);
    fireEvent.click(ticks()[0]);
    click("Rescan 1");
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Rescan" }));
    await waitFor(() => expect(notifications.info).toHaveBeenCalled());
    expect(String(notifications.info.mock.calls[0][0])).toContain("Nothing was changed");
  });
});

describe("what the scan Jobs say about a waiting row", () => {
  const labels = {
    "app.kubernetes.io/managed-by": "trivy-operator",
    "trivy-operator.resource.kind": "ReplicaSet",
    "trivy-operator.resource.name": "alpha",
    "trivy-operator.resource.namespace": "demo",
  };
  const rescanAlpha = async () => {
    const ctx = stock();
    const P = Page();
    render(<P extension={extension} />);
    fireEvent.click(ticks()[0]);
    click("Rescan 1");
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Rescan" }));
    await waitFor(() => expect(notifications.ok).toHaveBeenCalled());
    return ctx;
  };
  const labelAlphaReport = () => labels;

  it("shows Queued while no Job exists", async () => {
    await rescanAlpha();
    await waitFor(() => expect(screen.getByText(/^Queued/)).toBeTruthy());
  });

  it("shows Scanning while the scan pod runs", async () => {
    scanApi.jobs = [{ metadata: { name: "j", labels: labelAlphaReport() }, status: { active: 1 } }];
    scanApi.pods = [
      {
        metadata: { name: "p", labels: { ...labelAlphaReport(), "job-name": "j" } },
        status: { phase: "Running", containerStatuses: [{ name: "c", state: { running: {} } }] },
      },
    ];
    await rescanAlpha();
    await waitFor(() => expect(screen.getByText(/^Scanning/)).toBeTruthy());
  });

  it("shows why a scan failed, in the row", async () => {
    scanApi.jobs = [{ metadata: { name: "j", labels: labelAlphaReport() }, status: { active: 1 } }];
    scanApi.pods = [
      {
        metadata: { name: "p", labels: { ...labelAlphaReport(), "job-name": "j" } },
        status: {
          phase: "Failed",
          containerStatuses: [
            {
              name: "c",
              state: { terminated: { exitCode: 1, message: "\t* remote error: MANIFEST_UNKNOWN: manifest unknown" } },
            },
          ],
        },
      },
    ];
    await rescanAlpha();
    await waitFor(() => expect(screen.getByText("Scan failed")).toBeTruthy());
    expect(screen.getByText("The image or tag is not in the registry")).toBeTruthy();
  });

  it("falls back to Rescanning when the Jobs cannot be read", async () => {
    scanApi.fail = true;
    await rescanAlpha();
    await waitFor(() => expect(screen.getByText(/^Rescanning/)).toBeTruthy());
  });
});
