// What the Overview shows, as pure functions over the reports in the stores.

import {
  addCounts,
  countFixable,
  emptyCounts,
  hasFix,
  latestTimestamp,
  type SeverityCounts,
  severityCounts,
  totalCount,
} from "../api/trivy/report-model";

import type { Vulnerability } from "../api/trivy/common";

interface WithSummary {
  report?: {
    summary?: Parameters<typeof severityCounts>[0];
    artifact?: { repository?: string; tag?: string; digest?: string };
  };
}

/**
 * How many different images the reports are about. Each container of each workload has its own
 * report, so three replicas of one image are three reports but one image.
 */
export function distinctImages(items: WithSummary[]): number {
  const images = new Set<string>();
  for (const item of items) {
    const artifact = item.report?.artifact;
    if (artifact?.repository) images.add(`${artifact.repository}:${artifact.tag ?? ""}@${artifact.digest ?? ""}`);
  }
  return images.size;
}

export type SourceState = "ok" | "loading" | "failed" | "unavailable";

/** Whether a kind's reports can be read: not there (CRD missing), failed to load, loading, or ready. */
export function sourceState(store: { isLoaded?: boolean; failedLoading?: boolean } | null | undefined): SourceState {
  if (!store) return "unavailable";
  if (store.failedLoading) return "failed";
  return store.isLoaded ? "ok" : "loading";
}

export interface TileAvailability {
  /** Some data can be shown: false means the tile says "Not available" instead of a number. */
  available: boolean;
  /** How many of the tile's sources are missing or failed. */
  missing: number;
  /** Why nothing can be shown; undefined while something can. */
  reason?: "failed" | "unavailable";
}

/** A tile reads several kinds. It shows what it has, and says so when sources are missing. */
export function tileAvailability(states: SourceState[]): TileAvailability {
  const missing = states.filter((s) => s === "failed" || s === "unavailable").length;
  const usable = states.some((s) => s === "ok" || s === "loading");
  if (usable) return { available: true, missing, reason: undefined };
  return { available: false, missing, reason: states.includes("failed") ? "failed" : "unavailable" };
}

export interface KindSummary {
  /** How many reports there are. */
  reports: number;
  /** Findings by severity, summed over the reports. */
  counts: SeverityCounts;
  total: number;
}

export function summarizeKind(...lists: WithSummary[][]): KindSummary {
  let counts = emptyCounts();
  let reports = 0;
  for (const list of lists) {
    for (const item of list) {
      reports++;
      counts = addCounts(counts, severityCounts(item.report?.summary));
    }
  }
  return { reports, counts, total: totalCount(counts) };
}

interface VulnerabilityLike extends WithSummary {
  report?: WithSummary["report"] & { vulnerabilities?: Vulnerability[] };
}

/** Vulnerabilities with a published fix, summed over the reports. */
export function fixableTotal(...lists: VulnerabilityLike[][]): number {
  return lists.flat().reduce((sum, item) => sum + countFixable(item.report?.vulnerabilities), 0);
}

/**
 * The reports with the most severe findings: most critical first, then most high, then
 * medium and low. Reports with nothing to fix are left out.
 */
export function mostExposed<T extends WithSummary>(items: T[], limit: number): T[] {
  return items
    .map((item) => ({ item, c: severityCounts(item.report?.summary) }))
    .filter(({ c }) => totalCount(c) > 0)
    .sort((a, b) => b.c.critical - a.c.critical || b.c.high - a.c.high || b.c.medium - a.c.medium || b.c.low - a.c.low)
    .slice(0, limit)
    .map(({ item }) => item);
}

export interface BenchmarkRow {
  id: string;
  title: string;
  failing: number;
  passing: number;
}

interface ComplianceLike {
  metadata: { name?: string };
  spec?: { compliance?: { title?: string } };
  status?: { summary?: { failCount?: number; passCount?: number } };
}

export function benchmarkRows(items: ComplianceLike[]): BenchmarkRow[] {
  return items
    .map((item) => ({
      id: item.metadata.name ?? "",
      title: item.spec?.compliance?.title ?? item.metadata.name ?? "",
      failing: item.status?.summary?.failCount ?? 0,
      passing: item.status?.summary?.passCount ?? 0,
    }))
    .sort((a, b) => b.failing - a.failing || a.title.localeCompare(b.title));
}

interface VulnerabilityItem extends VulnerabilityLike {
  report?: VulnerabilityLike["report"] & { updateTimestamp?: string };
}

export interface Headline {
  critical: number;
  /** Distinct images with at least one critical finding. */
  criticalImages: number;
  /** Critical findings an upgrade clears. */
  criticalFixable: number;
  /** When the newest vulnerability scan finished. */
  lastScan?: string;
}

export function headline(...lists: VulnerabilityItem[][]): Headline {
  const items = lists.flat();
  let critical = 0;
  let criticalFixable = 0;
  for (const item of items) {
    const c = severityCounts(item.report?.summary).critical;
    critical += c;
    criticalFixable += (item.report?.vulnerabilities ?? []).filter(
      (v) => v.severity === "CRITICAL" && hasFix(v),
    ).length;
  }
  return {
    critical,
    criticalImages: distinctImages(items.filter((i) => severityCounts(i.report?.summary).critical > 0)),
    criticalFixable,
    lastScan: latestTimestamp(items.map((i) => i.report?.updateTimestamp)),
  };
}

export interface FixFirstRow<T> {
  item: T;
  counts: SeverityCounts;
  critical: number;
  high: number;
  /** Findings in the report, and how many of them an upgrade clears. */
  total: number;
  fixable: number;
}

/** Reports with critical or high findings, the worst first: where upgrading pays off most. */
export function fixFirst<T extends VulnerabilityLike>(items: T[], limit: number): FixFirstRow<T>[] {
  return items
    .map((item) => {
      const c = severityCounts(item.report?.summary);
      return {
        item,
        counts: c,
        critical: c.critical,
        high: c.high,
        total: totalCount(c),
        fixable: countFixable(item.report?.vulnerabilities),
      };
    })
    .filter((row) => row.critical + row.high > 0)
    .sort((a, b) => b.critical - a.critical || b.high - a.high || b.fixable - a.fixable)
    .slice(0, limit);
}
