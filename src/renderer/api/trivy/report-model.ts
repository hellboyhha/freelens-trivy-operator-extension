// Pure functions over the report shapes: no host API, so they run under vitest.
// Pages and drawers call these instead of repeating the arithmetic.

import type { Artifact, Check, ExposedSecret, SbomComponent, Severity, SeveritySummary, Vulnerability } from "./common";

export type SeverityKey = "critical" | "high" | "medium" | "low" | "unknown";

/** Worst first: the order severities are shown and sorted in. */
export const SEVERITY_KEYS: readonly SeverityKey[] = ["critical", "high", "medium", "low", "unknown"];

export type SeverityCounts = Record<SeverityKey, number>;

export function emptyCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
}

export function severityCounts(summary?: SeveritySummary): SeverityCounts {
  return {
    critical: summary?.criticalCount ?? 0,
    high: summary?.highCount ?? 0,
    medium: summary?.mediumCount ?? 0,
    low: summary?.lowCount ?? 0,
    unknown: summary?.unknownCount ?? 0,
  };
}

/**
 * One number to sort reports by severity: a single critical outranks any number of highs, a high
 * any number of mediums, and so on. Counts are capped at 9,999 per band, far above a real image.
 */
export function severityWeight(counts: SeverityCounts): number {
  const cap = (n: number) => Math.min(n, 9999);
  const unknown = counts.unknown > 0 ? 0.5 : 0; // above a clean report, below a single low
  return cap(counts.critical) * 1e12 + cap(counts.high) * 1e8 + cap(counts.medium) * 1e4 + cap(counts.low) + unknown;
}

export function addCounts(a: SeverityCounts, b: SeverityCounts): SeverityCounts {
  return {
    critical: a.critical + b.critical,
    high: a.high + b.high,
    medium: a.medium + b.medium,
    low: a.low + b.low,
    unknown: a.unknown + b.unknown,
  };
}

export function totalCount(counts: SeverityCounts): number {
  return counts.critical + counts.high + counts.medium + counts.low + counts.unknown;
}

const RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4, NONE: 5 };

/** 0 for CRITICAL up to 5 for NONE; anything the operator may add later sorts last. */
export function severityRank(severity?: Severity | string): number {
  return RANK[(severity ?? "").toUpperCase()] ?? 6;
}

type Finding = { severity?: Severity; score?: number; vulnerabilityID?: string; checkID?: string; ruleID?: string };

/** Severity first, then the higher score, then the id, so a list is stable between refreshes. */
export function compareFindings(a: Finding, b: Finding): number {
  return (
    severityRank(a.severity) - severityRank(b.severity) ||
    (b.score ?? 0) - (a.score ?? 0) ||
    (a.vulnerabilityID ?? a.checkID ?? a.ruleID ?? "").localeCompare(b.vulnerabilityID ?? b.checkID ?? b.ruleID ?? "")
  );
}

export function sortedVulnerabilities(vulnerabilities: Vulnerability[] = []): Vulnerability[] {
  return [...vulnerabilities].sort(compareFindings);
}

export function sortedSecrets(secrets: ExposedSecret[] = []): ExposedSecret[] {
  return [...secrets].sort(compareFindings);
}

/** A fix is published when the operator names a fixed version. */
export function hasFix(vulnerability: Vulnerability): boolean {
  return Boolean(vulnerability.fixedVersion);
}

export function countFixable(vulnerabilities: Vulnerability[] = []): number {
  return vulnerabilities.filter(hasFix).length;
}

/** The checks that failed, worst first; passed checks are not findings. */
export function failedChecks(checks: Check[] = []): Check[] {
  return checks.filter((check) => check.success === false).sort(compareFindings);
}

export function passedChecks(checks: Check[] = []): number {
  return checks.filter((check) => check.success === true).length;
}

/** `repository:tag`, or the digest when the image has no tag. */
export function imageOf(artifact?: Artifact): string {
  if (!artifact?.repository) return "";
  if (artifact.tag) return `${artifact.repository}:${artifact.tag}`;
  return artifact.digest ? `${artifact.repository}@${artifact.digest}` : artifact.repository;
}

export interface ResourceRef {
  kind: string;
  /** Empty when the operator hashed a name that is too long for a label and nothing else names it. */
  name: string;
  namespace: string;
  container?: string;
}

interface ReportMetadata {
  namespace?: string;
  labels?: Record<string, string>;
  ownerReferences?: { kind?: string; name?: string }[];
}

const LABEL = {
  kind: "trivy-operator.resource.kind",
  name: "trivy-operator.resource.name",
  namespace: "trivy-operator.resource.namespace",
  container: "trivy-operator.container.name",
};

/**
 * The workload or resource a report is about. The operator writes it in labels and also
 * sets an owner reference on namespaced reports; the label is used first and the owner
 * reference covers names too long for a label (the operator then writes `name-hash`).
 */
export function resourceOf(metadata?: ReportMetadata): ResourceRef {
  const labels = metadata?.labels ?? {};
  const owner = metadata?.ownerReferences?.[0];
  return {
    kind: labels[LABEL.kind] ?? owner?.kind ?? "",
    name: labels[LABEL.name] ?? owner?.name ?? "",
    namespace: labels[LABEL.namespace] ?? metadata?.namespace ?? "",
    container: labels[LABEL.container],
  };
}

/** `Kind/name`, or just the kind when the name is unknown. */
export function resourceLabel(ref: ResourceRef): string {
  return ref.name ? `${ref.kind}/${ref.name}` : ref.kind;
}

/** Link to the finding's page in Aqua's database; null when the id is not one of theirs. */
export function avdUrl(checkId?: string): string | null {
  return checkId && /^AVD-[A-Z]+-\d+$/.test(checkId)
    ? `https://avd.aquasec.com/misconfig/${checkId.toLowerCase()}`
    : null;
}

/** The first failed check's title and how many more failed; null when nothing failed. */
export function worstIssue(checks: Check[] = []): { title: string; more: number } | null {
  const failed = failedChecks(checks);
  return failed.length
    ? { title: failed[0].title ?? failed[0].checkID ?? "Failed check", more: failed.length - 1 }
    : null;
}

/** The newest of several ISO timestamps. */
export function latestTimestamp(timestamps: (string | undefined)[]): string | undefined {
  return timestamps
    .filter((t): t is string => Boolean(t) && !Number.isNaN(Date.parse(t as string)))
    .sort((a, b) => Date.parse(b) - Date.parse(a))[0];
}

/**
 * Best-effort version order: digit runs compare as numbers, a pre-release sorts before its release.
 * Good enough to pick the newest of a few fixed versions; not a package manager.
 */
export function compareVersions(a: string, b: string): number {
  const left = versionKey(a);
  const right = versionKey(b);
  return left < right ? -1 : left > right ? 1 : 0;
}

/** Trivy may list several fixed versions ("1.2.9, 2.0.1"): prefer the line the package is on, else the newest. */
export function pickFixedVersion(installed: string | undefined, fixed: string | undefined): string | undefined {
  const candidates = (fixed ?? "")
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean);
  if (candidates.length === 0) return undefined;
  const major = /\d+/.exec(installed ?? "")?.[0];
  const sameLine = major ? candidates.filter((v) => /\d+/.exec(v)?.[0] === major) : [];
  return (sameLine.length ? sameLine : candidates).sort(compareVersions).pop();
}

export interface PackageGroup {
  name: string;
  installed: string;
  /** The version that clears every fixable finding of the package; undefined when none has a fix. */
  fixed?: string;
  severity: Severity | undefined;
  /** Every finding of the package, worst first. */
  ids: string[];
  /** The same findings with their advisory link and severity. */
  findings: { id: string; link?: string; severity?: Severity }[];
  /** How many of them the upgrade clears. */
  clears: number;
  counts: SeverityCounts;
}

/** Findings grouped by the package they are in: what to upgrade, worst packages first. */
export function groupByPackage(vulnerabilities: Vulnerability[] = []): PackageGroup[] {
  const groups = new Map<string, Vulnerability[]>();
  for (const v of vulnerabilities) {
    const key = `${v.resource ?? ""}@${v.installedVersion ?? ""}`;
    groups.set(key, [...(groups.get(key) ?? []), v]);
  }
  return [...groups.values()]
    .map((items) => {
      const sorted = [...items].sort(compareFindings);
      const fixedVersions = sorted
        .map((v) => pickFixedVersion(v.installedVersion, v.fixedVersion))
        .filter((v): v is string => Boolean(v));
      let counts = emptyCounts();
      for (const v of sorted) counts = addCounts(counts, severityCounts(summaryOfOne(v.severity)));
      return {
        name: sorted[0].resource ?? "unknown",
        installed: sorted[0].installedVersion ?? "",
        fixed: [...fixedVersions].sort(compareVersions).pop(),
        severity: sorted[0].severity,
        ids: sorted.map((v) => v.vulnerabilityID ?? "").filter(Boolean),
        findings: sorted
          .filter((v) => v.vulnerabilityID)
          .map((v) => ({ id: v.vulnerabilityID as string, link: v.primaryLink, severity: v.severity })),
        clears: fixedVersions.length,
        counts,
      };
    })
    .sort(
      (a, b) =>
        severityRank(a.severity) - severityRank(b.severity) ||
        b.clears - a.clears ||
        b.ids.length - a.ids.length ||
        a.name.localeCompare(b.name),
    );
}

function summaryOfOne(severity?: Severity): SeveritySummary {
  return {
    criticalCount: severity === "CRITICAL" ? 1 : 0,
    highCount: severity === "HIGH" ? 1 : 0,
    mediumCount: severity === "MEDIUM" ? 1 : 0,
    lowCount: severity === "LOW" ? 1 : 0,
    unknownCount: severity === "UNKNOWN" ? 1 : 0,
  };
}

/** The upgrade list as text to paste into a ticket. */
export function ticketText(groups: PackageGroup[], context: { workload: string; image: string }): string {
  const lines = groups
    .filter((g) => g.fixed)
    .map(
      (g) =>
        `- ${g.name} ${g.installed} -> ${g.fixed}: clears ${g.clears} CVE${g.clears === 1 ? "" : "s"} (${g.ids.slice(0, 5).join(", ")}${g.ids.length > 5 ? ", ..." : ""})`,
    );
  return [
    `Upgrades for ${context.workload} (${context.image}):`,
    ...(lines.length ? lines : ["- nothing has a published fix"]),
  ].join("\n");
}

/**
 * A version as a string that sorts the way people read versions: every run of digits is padded,
 * so "1.10" sorts after "1.9". Plain string comparison of the keys gives the order.
 */
export function versionKey(version?: string): string {
  const parts = version?.match(/\d+|[a-zA-Z]+/g) ?? [];
  if (parts.length === 0) return "";
  const pad = (part: string) => (/^\d+$/.test(part) ? part.padStart(8, "0") : part);
  const pre = parts.findIndex((part) => PRE_RELEASE.has(part.toLowerCase()));
  // A pre-release ("1.0.0rc1") must sort before the release it leads to, but a plain string compare
  // puts a shorter key first. So a release ends in "0" (shorter than any padded number, so a packaging
  // revision such as "1.0.0-1" still sorts after it) and a pre-release gets "-" (below "0") in the
  // place where its tag starts.
  if (pre >= 0) return `${parts.slice(0, pre).map(pad).join(".")}.-.${parts.slice(pre).map(pad).join(".")}`;
  return `${parts.map(pad).join(".")}.0`;
}

const PRE_RELEASE = new Set(["alpha", "beta", "rc", "pre", "preview", "snapshot", "dev"]);

export interface PackageMatch {
  name: string;
  version: string;
  purl: string;
}

interface IndexedComponent extends PackageMatch {
  /** name, version and purl in one lowercase string: what a query is looked up in. */
  text: string;
}

// An SBOM can hold thousands of components and the search runs on every keystroke, so each
// component list is lowercased once and kept for as long as the report object lives.
const indexes = new WeakMap<SbomComponent[], IndexedComponent[]>();

function indexOf(components: SbomComponent[]): IndexedComponent[] {
  let index = indexes.get(components);
  if (!index) {
    index = components.map((c) => {
      const name = c.name ?? "";
      const version = c.version ?? "";
      const purl = c.purl ?? "";
      return { name, version, purl, text: `${name} ${version} ${purl}`.toLowerCase() };
    });
    indexes.set(components, index);
  }
  return index;
}

/**
 * The components a query finds. The query is split into words; a component matches when its name,
 * version or purl contains every word (case does not matter). Matches come by name, oldest
 * version first, and an empty query finds nothing.
 */
export function matchPackages(components: SbomComponent[] | undefined, query: string): PackageMatch[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (!components || words.length === 0) return [];
  return indexOf(components)
    .filter((c) => words.every((word) => c.text.includes(word)))
    .map(({ name, version, purl }) => ({ name, version, purl }))
    .sort((a, b) => a.name.localeCompare(b.name) || compareVersions(a.version, b.version));
}
