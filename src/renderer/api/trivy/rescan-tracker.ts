// Which reports the user asked to rescan and the operator has not yet replaced, and what the
// operator's scan Jobs say about each.
//
// It lives in the module, not in a page, so a wait survives moving between pages of the extension.
// Each cluster has its own window, so one tracker per window is one per cluster. While something
// waits it reads the scan Jobs every few seconds (a read-only list); it stops when nothing waits.

import { keyOf, type Pending, pendingFor, type ReportLike, resolvePending } from "./rescan-model";
import { fetchScanActivity } from "./scan-activity";
import { type Activity, observe, usesScanJob } from "./scan-status-model";

export interface TrackerOptions {
  /** Reads the scan Jobs and pods; null when they cannot be read. */
  fetchActivity?: () => Promise<Activity | null>;
  intervalMs?: number;
}

const DEFAULT_INTERVAL_MS = 5000;

export class RescanTracker {
  private pending: Pending<ReportLike & any>[] = [];
  private listeners = new Set<() => void>();
  private timer: ReturnType<typeof setInterval> | undefined;

  constructor(private readonly options: TrackerOptions = {}) {}

  list(): Pending<any>[] {
    return this.pending;
  }

  add<T extends ReportLike>(items: T[], now: number = Date.now()): void {
    if (items.length === 0) return;
    const keys = new Set(items.map(keyOf));
    this.pending = [...this.pending.filter((p) => !keys.has(p.key)), ...items.map((item) => pendingFor(item, now))];
    this.emit();
    this.startPolling();
  }

  /** Ends the wait of every report that has been replaced by a new one. */
  reconcile<T extends ReportLike>(items: T[]): void {
    if (this.pending.length === 0) return;
    const remaining = resolvePending(this.pending, items);
    if (remaining.length === this.pending.length) return;
    this.pending = remaining;
    this.emit();
    this.stopPollingIfIdle();
  }

  dismiss(key: string): void {
    this.pending = this.pending.filter((p) => p.key !== key);
    this.emit();
    this.stopPollingIfIdle();
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private emit(): void {
    for (const listener of this.listeners) listener();
  }

  private watched(): boolean {
    return this.pending.some((p) => usesScanJob(p.item.kind));
  }

  private startPolling(): void {
    if (!this.options.fetchActivity || !this.watched()) return;
    void this.poll();
    if (this.timer === undefined) {
      this.timer = setInterval(() => void this.poll(), this.options.intervalMs ?? DEFAULT_INTERVAL_MS);
    }
  }

  private stopPollingIfIdle(): void {
    if (this.timer !== undefined && !this.watched()) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }

  /** One read of the Jobs, folded into every waiting report that a Job makes. */
  private async poll(): Promise<void> {
    if (!this.options.fetchActivity || !this.watched()) return;
    let activity: Activity | null;
    try {
      activity = await this.options.fetchActivity();
    } catch {
      return;
    }
    if (!activity || !this.watched()) return;
    let changed = false;
    this.pending = this.pending.map((p) => {
      const scan = observe(p.item, activity, p.scan);
      if (JSON.stringify(scan) === JSON.stringify(p.scan)) return p;
      changed = true;
      return { ...p, scan };
    });
    if (changed) this.emit();
  }
}

/** The tracker the pages share. */
export const rescanTracker = new RescanTracker({ fetchActivity: fetchScanActivity });
