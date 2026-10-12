// @vitest-environment jsdom

// Renders every drawer with the synthetic fixtures. The host components are replaced by stubs that
// print their label and children, so this checks the drawers' own logic: they must not throw (an
// error page would be logged) and must show what the report holds.

import { Common, Renderer } from "@freelensapp/extensions";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fixture } from "../../../test/fixtures";
import { notifications, testStores } from "../../../test/freelens-extensions";
import { selectableStore } from "../../../test/stores";
import { ConfigAuditReport, ExposedSecretReport, SbomReport, VulnerabilityReport } from "../api/trivy";
import { rescanTracker } from "../api/trivy/rescan-tracker";
import { ChecksDetails, ComplianceDetails, SbomDetails, SecretDetails, VulnerabilityDetails } from "./report-details";
import { WorkloadDetails } from "./workload-details";

import type { Renderer as RendererTypes } from "@freelensapp/extensions";

const extension = {} as RendererTypes.LensExtension;

beforeEach(() => {
  vi.mocked(Common.logger.error).mockClear();
  testStores.clear();
});
afterEach(() => {
  cleanup();
  expect(Common.logger.error, "a drawer fell back to the error page").not.toHaveBeenCalled();
});

describe("VulnerabilityDetails", () => {
  it("groups the findings by package, worst first, with the version to upgrade to", () => {
    const { container } = render(
      <VulnerabilityDetails object={fixture("vulnerabilityreport")} extension={extension} />,
    );
    const text = container.textContent ?? "";
    expect(text).toContain("What to upgrade");
    expect(text).toContain("1.0.0 → 1.0.2");
    expect(text).toContain("clears 2 CVEs");
    expect(text).toContain("no fix yet");
    expect(text).toContain("demo/web:1.4.2");
    expect(text.indexOf("libexample")).toBeLessThan(text.indexOf("libsample"));
  });

  it("lists every CVE on request and narrows to the fixable ones with a chip", () => {
    const { container } = render(
      <VulnerabilityDetails object={fixture("vulnerabilityreport")} extension={extension} />,
    );
    fireEvent.click(screen.getByText("All CVEs"));
    expect(container.textContent).toContain("CVE-2099-0002");
    expect(container.textContent).toContain("no fix");
    fireEvent.click(screen.getByText("With a fix"));
    expect(container.textContent).not.toContain("CVE-2099-0002");
    expect(container.textContent).toContain("CVE-2099-0003");
  });

  it("shows the first 100 packages and the rest on request", () => {
    const base = fixture("vulnerabilityreport");
    const vulnerabilities = Array.from({ length: 130 }, (_, i) => ({
      vulnerabilityID: `CVE-${i}`,
      resource: `pkg${String(i).padStart(3, "0")}`,
      installedVersion: "1.0.0",
      fixedVersion: "1.0.1",
      severity: "HIGH" as const,
    }));
    const big = { ...base, report: { ...base.report, summary: { highCount: 130 }, vulnerabilities } };
    const { container } = render(<VulnerabilityDetails object={big} extension={extension} />);
    expect(container.textContent).toContain("30 more packages not shown");
    expect(container.textContent).not.toContain("pkg129");
    fireEvent.click(screen.getByText("Show all"));
    expect(container.textContent).toContain("pkg129");
    expect(container.textContent).not.toContain("more packages not shown");
  });

  it("puts the upgrade list on the clipboard for a ticket", () => {
    const writeText = vi.fn();
    Object.assign(navigator, { clipboard: { writeText } });
    render(<VulnerabilityDetails object={fixture("vulnerabilityreport")} extension={extension} />);
    fireEvent.click(screen.getByText("Copy for ticket"));
    expect(writeText).toHaveBeenCalledOnce();
    expect(writeText.mock.calls[0][0]).toContain("libexample 1.0.0 -> 1.0.2: clears 2 CVEs");
    expect(screen.getByText("Copied ✓")).toBeTruthy();
  });

  it("adds an Unknown count to the summary only when there are unknown findings", () => {
    const base = fixture("vulnerabilityreport");
    const { container } = render(<VulnerabilityDetails object={base} extension={extension} />);
    expect(container.textContent).not.toContain("unknown");
    cleanup();
    const withUnknown = { ...base, report: { ...base.report, summary: { ...base.report.summary, unknownCount: 7 } } };
    const again = render(<VulnerabilityDetails object={withUnknown} extension={extension} />);
    expect(again.container.textContent).toContain("unknown");
  });

  it("renders the cluster scoped kind and ignores other kinds", () => {
    const { container } = render(
      <VulnerabilityDetails object={fixture("clustervulnerabilityreport")} extension={extension} />,
    );
    expect(container.textContent).toContain("libexample");
    cleanup();
    const other = render(<VulnerabilityDetails object={fixture("configauditreport")} extension={extension} />);
    expect(other.container.textContent).toBe("");
  });

  it("copes with a report that has no findings", () => {
    const empty = { ...fixture("vulnerabilityreport"), report: {} };
    const { container } = render(<VulnerabilityDetails object={empty} extension={extension} />);
    expect(container.textContent).toContain("None found");
  });
});

describe("ComplianceDetails columns", () => {
  it("says Failing, not an abbreviation", () => {
    const { container } = render(
      <ComplianceDetails object={fixture("clustercompliancereport")} extension={extension} />,
    );
    expect(container.textContent).toContain("Failing");
  });
});

describe("SecretDetails", () => {
  it("shows the rule and file but never the matched text", () => {
    const { container } = render(<SecretDetails object={fixture("exposedsecretreport")} extension={extension} />);
    expect(container.textContent).toContain("Asymmetric Private Key");
    expect(container.textContent).toContain("/app/certs/demo.key");
    expect(container.textContent).toContain("Rotate each secret");
    expect(container.textContent).not.toContain("****");
  });
});

describe("ChecksDetails", () => {
  it("shows failed checks with their fix, and counts the passed ones", () => {
    const { container } = render(<ChecksDetails object={fixture("configauditreport")} extension={extension} />);
    expect(container.textContent).toContain("Root file system is not read-only");
    expect(container.textContent).toContain("Fix: Change");
    expect(container.textContent).toContain("1 checks passed");
    expect(container.querySelector('a[href="https://avd.aquasec.com/misconfig/avd-ksv-0014"]')).not.toBeNull();
  });
  it("says so when every check passed", () => {
    const { container } = render(<ChecksDetails object={fixture("infraassessmentreport")} extension={extension} />);
    expect(container.textContent).toContain("No failed checks");
  });
  it("serves every checks kind", () => {
    for (const name of [
      "clusterconfigauditreport",
      "rbacassessmentreport",
      "clusterrbacassessmentreport",
      "clusterinfraassessmentreport",
    ]) {
      const { container } = render(<ChecksDetails object={fixture(name)} extension={extension} />);
      expect(container.textContent, name).not.toBe("");
      cleanup();
    }
  });
});

describe("SbomDetails", () => {
  it("lists components and filters them", () => {
    const { container } = render(<SbomDetails object={fixture("sbomreport")} extension={extension} />);
    expect(container.textContent).toContain("libexample");
    expect(container.textContent).toContain("libsample");
    fireEvent.change(screen.getByPlaceholderText(/Filter/), { target: { value: "libsam" } });
    expect(container.textContent).not.toContain("libexample");
    expect(container.textContent).toContain("libsample");
  });
});

describe("ComplianceDetails", () => {
  it("lists failing controls first with the benchmark's metadata", () => {
    const { container } = render(
      <ComplianceDetails object={fixture("clustercompliancereport")} extension={extension} />,
    );
    expect(container.textContent).toContain("Demo Benchmark v1.0");
    expect(container.textContent).toContain("First control");
    expect(container.textContent).toContain("https://example.com/benchmark");
    expect(container.textContent?.indexOf("First control")).toBeLessThan(
      container.textContent?.indexOf("Second control") ?? 0,
    );
  });
});

describe("WorkloadDetails", () => {
  const deployment = (containers: string[] = ["web"]) => ({
    kind: "Deployment",
    metadata: { name: "web", namespace: "demo" },
    spec: { template: { spec: { containers: containers.map((name) => ({ name })) } } },
  });
  const storeOf = (reports: unknown[]) => ({ isLoaded: true, items: reports, loadAll: async () => {} });

  it("shows a card for the container and one for the configuration, each linking to its report", () => {
    testStores.set(VulnerabilityReport, storeOf([new VulnerabilityReport(fixture("vulnerabilityreport"))]));
    testStores.set(ExposedSecretReport, storeOf([new ExposedSecretReport(fixture("exposedsecretreport"))]));
    testStores.set(ConfigAuditReport, storeOf([new ConfigAuditReport(fixture("configauditreport"))]));
    const { container } = render(<WorkloadDetails object={deployment()} extension={extension} />);
    const text = container.textContent ?? "";
    expect(text).toContain("demo/web:1.4.2");
    expect(text).toContain("View report →");
    expect(text).toContain("Configuration");
    expect(text).toContain("exposed secret(s)");
    expect(text).toContain("fixable");
  });

  it("marks a container nobody scanned yet", () => {
    testStores.set(VulnerabilityReport, storeOf([new VulnerabilityReport(fixture("vulnerabilityreport"))]));
    const { container } = render(<WorkloadDetails object={deployment(["web", "migrate"])} extension={extension} />);
    expect(container.textContent).toContain("migrate");
    expect(container.textContent).toContain("not scanned yet");
  });

  it("says there are no reports for a workload nothing scanned", () => {
    testStores.set(VulnerabilityReport, storeOf([new VulnerabilityReport(fixture("vulnerabilityreport"))]));
    const other = { kind: "Deployment", metadata: { name: "other", namespace: "demo" } };
    const { container } = render(<WorkloadDetails object={other} extension={extension} />);
    expect(container.textContent).toContain("No Trivy Operator reports for this workload");
    // The section is titled with the product's full name.
    expect(container.textContent).toMatch(/^Trivy Operator/);
  });

  it("renders nothing when the operator's CRDs are absent", () => {
    const { container } = render(<WorkloadDetails object={deployment()} extension={extension} />);
    expect(container.textContent).toBe("");
  });
});

describe("Rescan from a drawer", () => {
  const kinds = [
    ["vulnerabilityreport", VulnerabilityReport, VulnerabilityDetails],
    ["exposedsecretreport", ExposedSecretReport, SecretDetails],
    ["configauditreport", ConfigAuditReport, ChecksDetails],
  ] as const;

  for (const [name, Kind, Details] of kinds) {
    it(`${name}: a Rescan button asks first, then deletes this report and closes the drawer`, async () => {
      const object = new (Kind as any)(fixture(name));
      const store = selectableStore([object]);
      testStores.set(Kind, store);
      vi.mocked(Renderer.Navigation.hideDetails).mockClear();
      for (const fn of Object.values(notifications)) fn.mockClear();
      const D = Details as any;
      render(<D object={object} extension={extension} />);
      fireEvent.click(screen.getByRole("button", { name: /Rescan/ }));
      expect(screen.getByText("Rescan this workload?")).toBeTruthy();
      expect(store.remove).not.toHaveBeenCalled();
      fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Rescan" }));
      await waitFor(() => expect(store.remove).toHaveBeenCalledWith(object));
      await waitFor(() => expect(notifications.ok).toHaveBeenCalled());
      expect(Renderer.Navigation.hideDetails).toHaveBeenCalled();
      expect(rescanTracker.list().map((p) => p.key)).toHaveLength(1);
      rescanTracker.dismiss(rescanTracker.list()[0].key);
    });
  }

  it("Cancel leaves the report and the drawer alone", () => {
    const object = new (VulnerabilityReport as any)(fixture("vulnerabilityreport"));
    const store = selectableStore([object]);
    testStores.set(VulnerabilityReport, store);
    vi.mocked(Renderer.Navigation.hideDetails).mockClear();
    render(<VulnerabilityDetails object={object} extension={extension} />);
    fireEvent.click(screen.getByRole("button", { name: /Rescan/ }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" }));
    expect(store.remove).not.toHaveBeenCalled();
    expect(Renderer.Navigation.hideDetails).not.toHaveBeenCalled();
  });

  it("is not on a Compliance report, whose deletion would delete the benchmark", () => {
    render(<ComplianceDetails object={fixture("clustercompliancereport")} extension={extension} />);
    expect(screen.queryByRole("button", { name: /Rescan/ })).toBeNull();
  });

  it("is not on an SBOM report, because the operator does not regenerate one that is deleted", () => {
    const object = new (SbomReport as any)(fixture("sbomreport"));
    testStores.set(SbomReport, selectableStore([object]));
    render(<SbomDetails object={object} extension={extension} />);
    expect(screen.queryByRole("button", { name: /Rescan/ })).toBeNull();
  });

  it("is not offered when the cluster has no store for the kind", () => {
    render(
      <VulnerabilityDetails
        object={new (VulnerabilityReport as any)(fixture("vulnerabilityreport"))}
        extension={extension}
      />,
    );
    expect(screen.queryByRole("button", { name: /Rescan/ })).toBeNull();
  });
});

describe("Rescan from a workload page", () => {
  const deployment = {
    kind: "Deployment",
    metadata: { name: "web", namespace: "demo" },
    spec: { template: { spec: { containers: [{ name: "web" }] } } },
  };
  const setup = () => {
    const make = (Kind: any, name: string) => {
      const base = fixture(name);
      return new Kind({
        ...base,
        metadata: {
          ...base.metadata,
          labels: {
            ...base.metadata.labels,
            "trivy-operator.resource.kind": "Deployment",
            "trivy-operator.resource.name": "web",
            "trivy-operator.resource.namespace": "demo",
          },
        },
      });
    };
    const vuln = make(VulnerabilityReport, "vulnerabilityreport");
    const secret = make(ExposedSecretReport, "exposedsecretreport");
    const config = make(ConfigAuditReport, "configauditreport");
    const stores = [vuln, secret, config].map((o, i) => {
      const store = selectableStore([o]);
      testStores.set([VulnerabilityReport, ExposedSecretReport, ConfigAuditReport][i], store);
      return store;
    });
    return { stores, items: [vuln, secret, config] };
  };

  it("offers one Rescan that deletes the workload's reports of every kind, after a single confirmation", async () => {
    const { stores, items } = setup();
    for (const fn of Object.values(notifications)) fn.mockClear();
    render(<WorkloadDetails object={deployment} extension={extension} />);
    fireEvent.click(screen.getByRole("button", { name: /Rescan/ }));
    const dialog = within(screen.getByRole("dialog"));
    expect(dialog.getByText("Rescan this workload?")).toBeTruthy();
    expect(dialog.getByText(/Deployment \/ web/)).toBeTruthy();
    expect(dialog.queryByRole("textbox")).toBeNull();
    fireEvent.click(dialog.getByRole("button", { name: "Rescan" }));
    await waitFor(() => stores.forEach((s, i) => expect(s.remove).toHaveBeenCalledWith(items[i])));
    await waitFor(() => expect(notifications.ok).toHaveBeenCalled());
    rescanTracker.list().forEach((p) => rescanTracker.dismiss(p.key));
  });

  it("has no button when the workload has no reports yet", () => {
    for (const Kind of [VulnerabilityReport, ExposedSecretReport, ConfigAuditReport])
      testStores.set(Kind, selectableStore([]));
    render(<WorkloadDetails object={deployment} extension={extension} />);
    expect(screen.queryByRole("button", { name: /Rescan/ })).toBeNull();
  });
});
