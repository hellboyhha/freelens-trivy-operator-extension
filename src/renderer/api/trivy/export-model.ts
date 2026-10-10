// Turns the reports of a list into CSV or JSON for audits and tickets. Pure: the page hands in the
// reports it shows, and gets text back.
//
// Two rules hold for every export. The matched text of an exposed secret is never written (the operator
// masks it, but the export has no use for it). A CSV cell that a spreadsheet would run as a formula is
// defused, because titles and package names come from outside the cluster.

import {
  countFixable,
  failedChecks,
  imageOf,
  resourceOf,
  severityCounts,
  sortedSecrets,
  sortedVulnerabilities,
} from "./report-model";

import type { Check, ExposedSecret, SbomReportData, Vulnerability } from "./common";

type Cell = string | number | undefined;

/** The part of a report object the export reads. */
interface ReportItem {
  kind?: string;
  metadata?: Parameters<typeof resourceOf>[0];
  report?: any;
}

type Shape = "vulnerability" | "secret" | "checks" | "sbom" | "other";

function shapeOf(kind?: string): Shape {
  const k = kind ?? "";
  if (/Vulnerability/.test(k)) return "vulnerability";
  if (/ExposedSecret/.test(k)) return "secret";
  if (/Sbom/.test(k)) return "sbom";
  if (/Config|Rbac|Infra/.test(k)) return "checks";
  return "other";
}

/** Whether a list of these reports can be exported as one row per finding. */
export const supportsFindings = (kind?: string): boolean =>
  ["vulnerability", "secret", "checks"].includes(shapeOf(kind));

/** CSV cell: quoted when it holds a comma, quote or line break; formula-looking text gets a leading quote mark. */
export function csvEscape(value: Cell): string {
  if (value === undefined || value === "") return "";
  let text = String(value);
  if (typeof value === "string" && /^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/** RFC 4180 text with CRLF line ends and a byte-order mark, so spreadsheets read the UTF-8 right. */
export function toCsv(columns: string[], rows: Cell[][]): string {
  return `\uFEFF${[columns, ...rows].map((row) => row.map(csvEscape).join(",")).join("\r\n")}\r\n`;
}

const IDENTITY = ["Namespace", "Workload kind", "Workload", "Container"];

function identity(item: ReportItem): Cell[] {
  const ref = resourceOf(item.metadata);
  return [item.metadata?.namespace ?? ref.namespace ?? "", ref.kind, ref.name, ref.container ?? ""];
}

const SEVERITY_COLUMNS = ["Critical", "High", "Medium", "Low", "Unknown"];

function reportRow(item: ReportItem, shape: Shape): { columns: string[]; row: Cell[] } {
  const report = item.report ?? {};
  const counts = severityCounts(report.summary);
  const severities: Cell[] = [counts.critical, counts.high, counts.medium, counts.low, counts.unknown];
  const image = imageOf(report.artifact);
  if (shape === "sbom") {
    const sbom = report as SbomReportData;
    return {
      columns: [...IDENTITY, "Image", "Components", "Format", "Scanned"],
      row: [
        ...identity(item),
        image,
        report.summary?.componentsCount ?? sbom.components?.components?.length ?? "",
        [sbom.components?.bomFormat, sbom.components?.specVersion].filter(Boolean).join(" "),
        report.updateTimestamp,
      ],
    };
  }
  const withImage = shape === "vulnerability" || shape === "secret";
  return {
    columns: [
      ...IDENTITY,
      ...(withImage ? ["Image"] : []),
      ...SEVERITY_COLUMNS,
      ...(shape === "vulnerability" ? ["Fixable"] : []),
      "Scanned",
    ],
    row: [
      ...identity(item),
      ...(withImage ? [image] : []),
      ...severities,
      ...(shape === "vulnerability" ? [countFixable(report.vulnerabilities)] : []),
      report.updateTimestamp,
    ],
  };
}

function findings(item: ReportItem, shape: Shape): Cell[][] {
  const report = item.report ?? {};
  const who = identity(item);
  const image = imageOf(report.artifact);
  if (shape === "vulnerability") {
    return sortedVulnerabilities(report.vulnerabilities).map((v: Vulnerability) => [
      ...who,
      image,
      v.severity,
      v.vulnerabilityID,
      v.resource,
      v.installedVersion,
      v.fixedVersion,
      v.title,
      v.primaryLink,
    ]);
  }
  if (shape === "secret") {
    return sortedSecrets(report.secrets).map((s: ExposedSecret) => [
      ...who,
      image,
      s.severity,
      s.ruleID,
      s.category,
      s.title,
      s.target,
    ]);
  }
  return failedChecks(report.checks).map((c: Check) => [
    ...who,
    c.severity,
    c.checkID,
    c.category,
    c.title,
    (c.messages ?? []).join(" "),
  ]);
}

function findingColumns(shape: Shape): string[] {
  if (shape === "vulnerability") {
    return [...IDENTITY, "Image", "Severity", "ID", "Package", "Installed", "Fixed", "Title", "Link"];
  }
  if (shape === "secret") return [...IDENTITY, "Image", "Severity", "Rule", "Category", "Title", "Target"];
  return [...IDENTITY, "Severity", "Check", "Category", "Title", "Message"];
}

/** The table of a list: a row per report, or a row per finding. */
export function exportTable(items: ReportItem[], mode: "reports" | "findings"): { columns: string[]; rows: Cell[][] } {
  const shape = shapeOf(items[0]?.kind);
  if (mode === "findings" && supportsFindings(items[0]?.kind)) {
    return { columns: findingColumns(shape), rows: items.flatMap((item) => findings(item, shape)) };
  }
  const first = reportRow(items[0] ?? {}, shape);
  return { columns: first.columns, rows: items.map((item) => reportRow(item, shape).row) };
}

/** The reports as JSON: identity, summary and findings. Components of an SBOM are left out, the secret text too. */
export function exportJson(items: ReportItem[], context: { cluster: string; when?: Date }): string {
  const reports = items.map((item) => {
    const shape = shapeOf(item.kind);
    const report = item.report ?? {};
    const ref = resourceOf(item.metadata);
    const base = {
      kind: item.kind,
      namespace: item.metadata?.namespace ?? ref.namespace ?? "",
      workload: { kind: ref.kind, name: ref.name, container: ref.container },
      image: shape === "vulnerability" || shape === "secret" || shape === "sbom" ? imageOf(report.artifact) : undefined,
      scanned: report.updateTimestamp,
      summary: report.summary,
    };
    if (shape === "vulnerability") return { ...base, findings: sortedVulnerabilities(report.vulnerabilities) };
    if (shape === "secret") {
      return {
        ...base,
        findings: sortedSecrets(report.secrets).map(({ match: _masked, ...rest }: ExposedSecret) => rest),
      };
    }
    if (shape === "checks") return { ...base, findings: failedChecks(report.checks) };
    return base;
  });
  return JSON.stringify(
    {
      exportedAt: (context.when ?? new Date()).toISOString(),
      cluster: context.cluster,
      count: reports.length,
      reports,
    },
    null,
    2,
  );
}

const slug = (text: string) =>
  text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");

const pad = (n: number) => String(n).padStart(2, "0");

/** `trivy-<what>[-<mode>][-<cluster>]-<yyyymmdd>.<ext>`, the date being the user's own day. */
export function exportFileName(what: string, cluster: string, when: Date, ext: "csv" | "json", mode?: string): string {
  const date = `${when.getFullYear()}${pad(when.getMonth() + 1)}${pad(when.getDate())}`;
  return ["trivy", slug(what), mode, slug(cluster), date].filter(Boolean).join("-") + `.${ext}`;
}
