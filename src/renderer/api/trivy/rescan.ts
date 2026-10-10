// Rescan: the one place the extension writes to the cluster.
//
// The Trivy Operator watches its report resources and scans a workload again when its report is
// missing, so a rescan is the deletion of that report. Nothing else here changes the cluster.
// `tools/architecture.mjs` allows cluster writes in this file only.

export type FailureReason = "forbidden" | "gone" | "other";

export interface ClassifiedError {
  reason: FailureReason;
  message: string;
}

/** The report resources can be deleted through the host store's `remove`. */
export interface RemovableStore<T> {
  remove(item: T): Promise<unknown>;
}

export interface RescanResult<T> {
  /** Deleted: the operator will scan these again. */
  requested: T[];
  /** Already gone when asked; the operator may be rescanning them now. */
  gone: T[];
  failed: { item: T; reason: FailureReason; message: string }[];
}

interface ErrorShape {
  code?: number;
  status?: number;
  reason?: string;
  message?: unknown;
  /** The host wraps the cluster's Status object (code, reason, message) in `error`. */
  error?: ErrorShape;
  messages?: unknown;
}

/**
 * Reads the error the host throws for a failed request: its `JsonApiErrorParsed` holds the cluster's
 * Status object in `error` and the readable lines in `messages`; other callers throw an Error or a string.
 */
export function classifyError(thrown: unknown): ClassifiedError {
  const top = (typeof thrown === "object" && thrown !== null ? thrown : {}) as ErrorShape;
  const inner = top.error && typeof top.error === "object" ? top.error : {};
  const lines = Array.isArray(top.messages) ? top.messages.filter((m): m is string => typeof m === "string") : [];
  const message =
    typeof thrown === "string"
      ? thrown
      : typeof top.message === "string"
        ? top.message
        : typeof inner.message === "string" && lines.length === 0
          ? inner.message
          : lines.length > 0
            ? lines.join(". ")
            : "Unknown error";
  const code = top.code ?? top.status ?? inner.code ?? inner.status;
  const reason = `${top.reason ?? ""} ${inner.reason ?? ""}`;
  if (code === 403 || /forbidden/i.test(reason) || /forbidden/i.test(message)) return { reason: "forbidden", message };
  if (code === 404 || /not ?found/i.test(reason) || /not ?found/i.test(message)) return { reason: "gone", message };
  return { reason: "other", message };
}

/** Rescans reports of different kinds: each goes to the store of its own kind. */
export async function rescanAcross<T>(
  storeOf: (item: T) => RemovableStore<T> | undefined,
  items: T[],
): Promise<RescanResult<T>> {
  const groups = new Map<RemovableStore<T> | undefined, T[]>();
  for (const item of items) {
    const store = storeOf(item);
    groups.set(store, [...(groups.get(store) ?? []), item]);
  }
  const result: RescanResult<T> = { requested: [], gone: [], failed: [] };
  for (const [store, group] of groups) {
    if (!store) {
      for (const item of group) {
        result.failed.push({ item, reason: "other", message: "This kind of report is not available in this cluster" });
      }
      continue;
    }
    const part = await rescanReports(store, group);
    result.requested.push(...part.requested);
    result.gone.push(...part.gone);
    result.failed.push(...part.failed);
  }
  return result;
}

/** Deletes each report so the operator scans its workload again. One failure does not stop the rest. */
export async function rescanReports<T>(store: RemovableStore<T>, items: T[]): Promise<RescanResult<T>> {
  const result: RescanResult<T> = { requested: [], gone: [], failed: [] };
  const outcomes = await Promise.allSettled(items.map((item) => store.remove(item)));
  outcomes.forEach((outcome, index) => {
    const item = items[index];
    if (outcome.status === "fulfilled") {
      result.requested.push(item);
      return;
    }
    const { reason, message } = classifyError(outcome.reason);
    if (reason === "gone") result.gone.push(item);
    else result.failed.push({ item, reason, message });
  });
  return result;
}
