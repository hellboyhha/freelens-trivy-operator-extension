import { describe, expect, it } from "vitest";
import { fixture } from "../../../../test/fixtures";
import { csvEscape, exportFileName, exportJson, exportTable, supportsFindings, toCsv } from "./export-model";

describe("csvEscape", () => {
  it("quotes what needs it and doubles the quotes", () => {
    expect(csvEscape("plain")).toBe("plain");
    expect(csvEscape("a,b")).toBe('"a,b"');
    expect(csvEscape('say "hi"')).toBe('"say ""hi"""');
    expect(csvEscape("two\nlines")).toBe('"two\nlines"');
  });
  it("defuses a cell a spreadsheet would run as a formula, since titles come from outside", () => {
    for (const bad of ["=1+1", "+cmd", "-2", "@SUM(A1)", "\tx", "\rx"]) {
      expect(csvEscape(bad).replace(/^"/, "").startsWith("'"), bad).toBe(true);
    }
    expect(csvEscape("-")).toBe("'-");
    expect(csvEscape("1.0.0-1")).toBe("1.0.0-1");
  });
  it("writes numbers and empty values as they are", () => {
    expect(csvEscape(3)).toBe("3");
    expect(csvEscape(undefined)).toBe("");
  });
});

describe("toCsv", () => {
  it("starts with a byte-order mark for spreadsheets, uses CRLF and quotes the header too", () => {
    const text = toCsv(["a", "b,c"], [["1", "x"]]);
    expect(text).toBe('\uFEFFa,"b,c"\r\n1,x\r\n');
  });
});

describe("exportTable: one row per report", () => {
  const vuln = Object.assign(fixture("vulnerabilityreport"), { kind: "VulnerabilityReport" });

  it("names the workload, image and counts, with the fixable count for vulnerabilities", () => {
    const { columns, rows } = exportTable([vuln], "reports");
    expect(columns).toEqual([
      "Namespace",
      "Workload kind",
      "Workload",
      "Container",
      "Image",
      "Critical",
      "High",
      "Medium",
      "Low",
      "Unknown",
      "Fixable",
      "Scanned",
    ]);
    expect(rows).toHaveLength(1);
    const row = Object.fromEntries(columns.map((c, i) => [c, rows[0][i]]));
    expect(row).toMatchObject({
      Namespace: "demo",
      Container: "web",
      Image: "demo/web:1.4.2",
      Critical: 1,
      Fixable: 2,
    });
    expect(row["Scanned"]).toBe(vuln.report.updateTimestamp);
  });

  it("has components and format for an SBOM instead of severity counts", () => {
    const { columns } = exportTable([Object.assign(fixture("sbomreport"), { kind: "SbomReport" })], "reports");
    expect(columns).toContain("Components");
    expect(columns).toContain("Format");
    expect(columns).not.toContain("Critical");
  });

  it("leaves the namespace empty for a cluster-wide report", () => {
    const item = Object.assign(fixture("clusterrbacassessmentreport"), { kind: "ClusterRbacAssessmentReport" });
    const { columns, rows } = exportTable([item], "reports");
    expect(rows[0][columns.indexOf("Namespace")]).toBe("");
  });
});

describe("exportTable: one row per finding", () => {
  it("lists each CVE of each report with its package and the fixed version", () => {
    const vuln = Object.assign(fixture("vulnerabilityreport"), { kind: "VulnerabilityReport" });
    const { columns, rows } = exportTable([vuln, vuln], "findings");
    expect(rows).toHaveLength(6);
    expect(columns).toEqual([
      "Namespace",
      "Workload kind",
      "Workload",
      "Container",
      "Image",
      "Severity",
      "ID",
      "Package",
      "Installed",
      "Fixed",
      "Title",
      "Link",
    ]);
    expect(rows[0][columns.indexOf("Severity")]).toBe("CRITICAL");
    expect(rows[0][columns.indexOf("ID")]).toBe("CVE-2099-0001");
  });

  it("lists secrets with the rule and the file, never the matched text", () => {
    const secret = Object.assign(fixture("exposedsecretreport"), { kind: "ExposedSecretReport" });
    const { columns, rows } = exportTable([secret], "findings");
    expect(columns).toContain("Target");
    expect(columns).not.toContain("Match");
    expect(rows[0].join("|")).not.toContain("****");
    expect(rows[0][columns.indexOf("Target")]).toBe("/app/certs/demo.key");
  });

  it("lists only the failed checks of a configuration report", () => {
    const config = Object.assign(fixture("configauditreport"), { kind: "ConfigAuditReport" });
    const failed = (config.report.checks as { success: boolean }[]).filter((c) => !c.success).length;
    const { columns, rows } = exportTable([config], "findings");
    expect(rows).toHaveLength(failed);
    expect(columns).toContain("Check");
    expect(columns).toContain("Message");
  });

  it("is only offered where reports hold findings", () => {
    expect(supportsFindings("VulnerabilityReport")).toBe(true);
    expect(supportsFindings("ExposedSecretReport")).toBe(true);
    expect(supportsFindings("ClusterRbacAssessmentReport")).toBe(true);
    expect(supportsFindings("SbomReport")).toBe(false);
    expect(supportsFindings("ClusterComplianceReport")).toBe(false);
  });
});

describe("exportJson", () => {
  const vuln = Object.assign(fixture("vulnerabilityreport"), { kind: "VulnerabilityReport" });
  it("holds the reports with their summary and findings, and says what and when", () => {
    const data = JSON.parse(exportJson([vuln], { cluster: "c1", when: new Date("2026-10-10T08:00:00Z") }));
    expect(data).toMatchObject({ exportedAt: "2026-10-10T08:00:00.000Z", cluster: "c1", count: 1 });
    expect(data.reports[0]).toMatchObject({ kind: "VulnerabilityReport", namespace: "demo", image: "demo/web:1.4.2" });
    expect(data.reports[0].summary.criticalCount).toBe(1);
    expect(data.reports[0].findings).toHaveLength(3);
  });
  it("leaves the components out of an SBOM, which can be tens of megabytes", () => {
    const sbom = Object.assign(fixture("sbomreport"), { kind: "SbomReport" });
    const data = JSON.parse(exportJson([sbom], { cluster: "c1" }));
    expect(data.reports[0].findings).toBeUndefined();
    expect(data.reports[0].components).toBeUndefined();
    expect(data.reports[0].summary).toBeDefined();
  });
  it("never carries the matched text of a secret", () => {
    const secret = Object.assign(fixture("exposedsecretreport"), { kind: "ExposedSecretReport" });
    expect(exportJson([secret], { cluster: "c" })).not.toContain("****");
  });
});

describe("exportFileName", () => {
  it("says what, which cluster and the date, in characters every system accepts", () => {
    expect(
      exportFileName("Vulnerabilities", "dev cluster/1", new Date("2026-10-10T08:00:00Z"), "csv", "findings"),
    ).toBe("trivy-vulnerabilities-findings-dev-cluster-1-20261010.csv");
    expect(exportFileName("SBOM", "", new Date("2026-10-10T08:00:00Z"), "json")).toBe("trivy-sbom-20261010.json");
  });
});
