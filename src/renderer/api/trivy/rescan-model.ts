// What the page knows about a rescan: pure functions, so they run without the host.
//
// Deleting a report removes it from the store; the operator writes a new one (same name, new uid)
// some seconds later. In between, the page keeps the deleted report to show a "Rescanning" row.

/** Without a new report after this long, the row says so instead of waiting forever. */
export const STALE_AFTER_MS = 10 * 60 * 1000;

import type { RescanResult } from "./rescan";
import type { ScanProgress } from "./scan-status-model";

export interface ReportLike {
  kind?: string;
  metadata: { name?: string; namespace?: string; uid?: string };
}

/** Kind, namespace and name: what survives a rescan, unlike the uid. */
export function keyOf(report: ReportLike): string {
  return `${report.kind ?? ""}/${report.metadata.namespace ?? ""}/${report.metadata.name ?? ""}`;
}

export interface Pending<T extends ReportLike> {
  key: string;
  item: T;
  /** The uid of the report that was deleted. */
  uid: string;
  requestedAt: number;
  /** What the scan Jobs showed so far; absent for reports no Job makes. */
  scan?: ScanProgress;
}

export function pendingFor<T extends ReportLike>(item: T, requestedAt: number): Pending<T> {
  return { key: keyOf(item), item, uid: item.metadata.uid ?? "", requestedAt };
}

/** Drops the waits whose report is back: the same name with a different uid. */
export function resolvePending<T extends ReportLike>(pending: Pending<T>[], items: T[]): Pending<T>[] {
  const uids = new Map<string, Set<string>>();
  for (const item of items) {
    const key = keyOf(item);
    uids.set(key, (uids.get(key) ?? new Set()).add(item.metadata.uid ?? ""));
  }
  return pending.filter((p) => {
    const present = uids.get(p.key);
    return !present || [...present].every((uid) => uid === p.uid);
  });
}

/** The waiting reports the store no longer holds: shown as "Rescanning" rows. */
export function ghostItems<T extends ReportLike>(pending: Pending<T>[], items: T[]): T[] {
  const present = new Set(items.map(keyOf));
  return pending.filter((p) => !present.has(p.key)).map((p) => p.item);
}

export type Phase = "rescanning" | "stale";

export function phaseOf(pending: Pending<ReportLike>, now: number): Phase {
  return now - pending.requestedAt >= STALE_AFTER_MS ? "stale" : "rescanning";
}

export function elapsedText(ms: number): string {
  const minutes = Math.floor(Math.max(0, ms) / 60_000);
  return minutes < 1 ? "<1m" : `${minutes}m`;
}

export interface WorkloadRef {
  kind: string;
  name: string;
  namespace: string;
}

export interface ConfirmPlan {
  count: number;
  /** Set when the reports are all one workload's: a single confirmation is enough. */
  workload?: WorkloadRef;
  /** Several reports at once: the cluster name must be typed. */
  needsTyping: boolean;
  /** What must be typed: the cluster's name, or "rescan" when it has none. */
  phrase: string;
  /** Each namespace once, cluster-wide reports as "(cluster-wide)". */
  namespaces: string[];
}

export function confirmPlan(items: ReportLike[], clusterName: string, workload?: WorkloadRef): ConfirmPlan {
  const namespaces = [...new Set(items.map((i) => i.metadata.namespace || "(cluster-wide)"))].sort();
  return {
    count: items.length,
    workload,
    needsTyping: items.length > 1 && !workload,
    phrase: clusterName.trim() || "rescan",
    namespaces,
  };
}

export function isConfirmed(plan: ConfirmPlan, typed: string): boolean {
  return !plan.needsTyping || typed.trim() === plan.phrase;
}

export interface OutcomeMessage {
  tone: "ok" | "error" | "info";
  text: string;
}

const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

/** What to tell the user once the deletes have been tried: one message per kind of outcome. */
export function describeOutcome<T extends ReportLike>(result: RescanResult<T>): OutcomeMessage[] {
  const messages: OutcomeMessage[] = [];
  const { requested, gone, failed } = result;

  if (requested.length > 0) {
    const n = requested.length;
    messages.push({
      tone: "ok",
      text: `Rescan requested for ${n} ${plural(n, "workload", "workloads")}. ${plural(n, "The new report usually appears", "The new reports usually appear")} within 2 to 5 minutes.`,
    });
  }

  const forbidden = failed.filter((f) => f.reason === "forbidden");
  if (forbidden.length > 0) {
    const kinds = [...new Set(forbidden.map((f) => f.item.kind ?? "report"))].join(", ");
    const namespaces = [...new Set(forbidden.map((f) => f.item.metadata.namespace).filter(Boolean))].sort();
    const where =
      namespaces.length === 0
        ? ""
        : ` in ${plural(namespaces.length, "namespace", "namespaces")} ${namespaces.join(", ")}`;
    messages.push({
      tone: "error",
      text: `Could not delete ${plural(forbidden.length, "the report", `${forbidden.length} reports`)}. Forbidden: your account may not delete ${kinds}${where}. Ask a cluster admin for the delete permission.`,
    });
  }

  const other = failed.filter((f) => f.reason === "other");
  if (other.length > 0) {
    const reasons = [...new Set(other.map((f) => f.message))].join("; ");
    messages.push({
      tone: "error",
      text: `Could not delete ${other.length} ${plural(other.length, "report", "reports")}: ${reasons}`,
    });
  }

  if (requested.length === 0 && failed.length === 0 && gone.length > 0) {
    messages.push({
      tone: "info",
      text: "Nothing was changed. The report was already gone; the operator may be rescanning it now.",
    });
  }
  return messages;
}
