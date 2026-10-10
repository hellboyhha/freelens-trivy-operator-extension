import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RescanTracker } from "./rescan-tracker";

const report = (name: string, uid: string) => ({
  kind: "VulnerabilityReport",
  metadata: { name, uid, namespace: "demo" },
});

describe("RescanTracker", () => {
  it("remembers a requested report with the time of the request", () => {
    const tracker = new RescanTracker();
    tracker.add([report("a", "1")], 1000);
    expect(tracker.list()).toHaveLength(1);
    expect(tracker.list()[0]).toMatchObject({ uid: "1", requestedAt: 1000 });
  });

  it("asking again for the same report restarts its clock instead of listing it twice", () => {
    const tracker = new RescanTracker();
    tracker.add([report("a", "1")], 1000);
    tracker.add([report("a", "2")], 5000);
    expect(tracker.list()).toHaveLength(1);
    expect(tracker.list()[0].requestedAt).toBe(5000);
  });

  it("forgets a report once a new one with the same name has appeared", () => {
    const tracker = new RescanTracker();
    tracker.add([report("a", "1"), report("b", "2")], 0);
    tracker.reconcile([report("a", "9")]);
    expect(tracker.list().map((p) => p.item.metadata.name)).toEqual(["b"]);
  });

  it("tells listeners when it changes, and only then", () => {
    const tracker = new RescanTracker();
    const listener = vi.fn();
    const stop = tracker.subscribe(listener);
    tracker.add([report("a", "1")], 0);
    expect(listener).toHaveBeenCalledTimes(1);
    tracker.reconcile([report("zzz", "3")]);
    expect(listener).toHaveBeenCalledTimes(1);
    tracker.reconcile([report("a", "9")]);
    expect(listener).toHaveBeenCalledTimes(2);
    stop();
    tracker.add([report("c", "4")], 0);
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it("can dismiss a stale wait", () => {
    const tracker = new RescanTracker();
    tracker.add([report("a", "1")], 0);
    tracker.dismiss("VulnerabilityReport/demo/a");
    expect(tracker.list()).toEqual([]);
  });
});

describe("RescanTracker polling the scan Jobs", () => {
  const labels = {
    "trivy-operator.resource.kind": "Deployment",
    "trivy-operator.resource.name": "web",
    "trivy-operator.resource.namespace": "demo",
  };
  const vuln = (name = "a") => ({
    kind: "VulnerabilityReport",
    metadata: { name, uid: "1", namespace: "demo", labels },
  });
  const activeJob = {
    jobs: [{ metadata: { name: "j", labels }, status: { active: 1 } }],
    pods: [
      {
        metadata: { name: "p", labels: { ...labels, "job-name": "j" } },
        status: { phase: "Running", containerStatuses: [{ name: "c", state: { running: {} } }] },
      },
    ],
  };

  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("reads the Jobs as soon as a report is added and shows what they say", async () => {
    const fetchActivity = vi.fn(async () => activeJob);
    const tracker = new RescanTracker({ fetchActivity });
    const listener = vi.fn();
    tracker.subscribe(listener);
    tracker.add([vuln()], 0);
    await vi.advanceTimersByTimeAsync(0);
    expect(fetchActivity).toHaveBeenCalledTimes(1);
    expect(tracker.list()[0].scan?.state).toEqual({ kind: "scanning" });
    expect(listener.mock.calls.length).toBeGreaterThanOrEqual(2);
  });

  it("asks again every few seconds, and stops once nothing waits", async () => {
    const fetchActivity = vi.fn(async () => activeJob);
    const tracker = new RescanTracker({ fetchActivity, intervalMs: 5000 });
    tracker.add([vuln()], 0);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(fetchActivity).toHaveBeenCalledTimes(3);
    tracker.dismiss(tracker.list()[0].key);
    await vi.advanceTimersByTimeAsync(20_000);
    expect(fetchActivity).toHaveBeenCalledTimes(3);
  });

  it("stops when the new report arrives", async () => {
    const fetchActivity = vi.fn(async () => activeJob);
    const tracker = new RescanTracker({ fetchActivity, intervalMs: 5000 });
    tracker.add([vuln()], 0);
    tracker.reconcile([{ ...vuln(), metadata: { ...vuln().metadata, uid: "2" } }]);
    const calls = fetchActivity.mock.calls.length;
    await vi.advanceTimersByTimeAsync(30_000);
    expect(fetchActivity).toHaveBeenCalledTimes(calls);
  });

  it("keeps the last state when the Jobs cannot be read, and survives a throwing fetch", async () => {
    const answers: (typeof activeJob | null | "throw")[] = [activeJob, null, "throw"];
    const fetchActivity = vi.fn(async () => {
      const a = answers.shift();
      if (a === "throw") throw new Error("forbidden");
      return a ?? null;
    });
    const tracker = new RescanTracker({ fetchActivity, intervalMs: 1000 });
    tracker.add([vuln()], 0);
    await vi.advanceTimersByTimeAsync(3000);
    expect(tracker.list()[0].scan?.state).toEqual({ kind: "scanning" });
  });

  it("does not poll for reports no Job makes", async () => {
    const fetchActivity = vi.fn(async () => activeJob);
    const tracker = new RescanTracker({ fetchActivity });
    tracker.add([{ kind: "ConfigAuditReport", metadata: { name: "c", uid: "1", namespace: "demo", labels } }], 0);
    await vi.advanceTimersByTimeAsync(20_000);
    expect(fetchActivity).not.toHaveBeenCalled();
  });
});
