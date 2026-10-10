import { describe, expect, it } from "vitest";
import {
  confirmPlan,
  describeOutcome,
  elapsedText,
  ghostItems,
  isConfirmed,
  keyOf,
  type Pending,
  phaseOf,
  resolvePending,
  STALE_AFTER_MS,
} from "./rescan-model";

/** `namespace` null means a cluster-scoped report. */
const report = (name: string, uid: string, namespace: string | null = "demo", kind = "VulnerabilityReport") => ({
  kind,
  metadata: { name, uid, namespace: namespace ?? undefined },
});
const pending = (item: ReturnType<typeof report>, requestedAt = 0): Pending<typeof item> => ({
  key: keyOf(item),
  item,
  uid: item.metadata.uid,
  requestedAt,
});

describe("keyOf", () => {
  it("identifies a report by kind, namespace and name, which survive a rescan", () => {
    expect(keyOf(report("r", "u1"))).toBe(keyOf(report("r", "u2")));
    expect(keyOf(report("r", "u1", "a"))).not.toBe(keyOf(report("r", "u1", "b")));
    expect(keyOf(report("r", "u1", null, "ClusterRbacAssessmentReport"))).toBe("ClusterRbacAssessmentReport//r");
  });
});

describe("resolvePending", () => {
  const old = report("r", "old");
  it("keeps a report waiting while the old one is gone", () => {
    expect(resolvePending([pending(old)], [])).toHaveLength(1);
  });
  it("ends the wait when a report with the same name but a new uid appears", () => {
    expect(resolvePending([pending(old)], [report("r", "new")])).toEqual([]);
  });
  it("keeps waiting while the old object is still there, since the delete may not have landed yet", () => {
    expect(resolvePending([pending(old)], [report("r", "old")])).toHaveLength(1);
  });
  it("leaves other waits alone", () => {
    const other = report("o", "x");
    expect(resolvePending([pending(old), pending(other)], [report("r", "new")]).map((p) => p.item)).toEqual([other]);
  });
});

describe("ghostItems", () => {
  it("lists the waiting reports the store no longer has, and not those that are back", () => {
    const a = report("a", "1");
    const b = report("b", "2");
    expect(ghostItems([pending(a), pending(b)], [report("b", "3")])).toEqual([a]);
  });
});

describe("phaseOf and elapsedText", () => {
  it("is rescanning for 10 minutes and then says no new report appeared", () => {
    const p = pending(report("r", "u"), 1000);
    expect(phaseOf(p, 1000 + STALE_AFTER_MS - 1)).toBe("rescanning");
    expect(phaseOf(p, 1000 + STALE_AFTER_MS)).toBe("stale");
  });
  it("words the elapsed time in minutes, and under a minute as such", () => {
    expect(elapsedText(5_000)).toBe("<1m");
    expect(elapsedText(60_000)).toBe("1m");
    expect(elapsedText(125_000)).toBe("2m");
    expect(elapsedText(-5)).toBe("<1m");
  });
});

describe("confirmPlan", () => {
  it("asks for a plain confirmation for one report, naming what it is", () => {
    const plan = confirmPlan([report("r", "u")], "dev-cluster");
    expect(plan).toMatchObject({ count: 1, needsTyping: false, namespaces: ["demo"] });
    expect(isConfirmed(plan, "")).toBe(true);
  });
  it("asks for the cluster name when several are selected", () => {
    const plan = confirmPlan([report("a", "1"), report("b", "2", "kube-system")], "dev-cluster");
    expect(plan).toMatchObject({
      count: 2,
      needsTyping: true,
      phrase: "dev-cluster",
      namespaces: ["demo", "kube-system"],
    });
    expect(isConfirmed(plan, "dev-clust")).toBe(false);
    expect(isConfirmed(plan, "Dev-Cluster")).toBe(false);
    expect(isConfirmed(plan, "  dev-cluster ")).toBe(true);
  });
  it("falls back to the word rescan when the cluster has no name to type", () => {
    const plan = confirmPlan([report("a", "1"), report("b", "2")], "");
    expect(plan.phrase).toBe("rescan");
    expect(isConfirmed(plan, "rescan")).toBe(true);
  });
  it("names cluster-wide reports as such and lists each namespace once", () => {
    const plan = confirmPlan([report("a", "1"), report("b", "2"), report("c", "3", null, "ClusterSbomReport")], "c");
    expect(plan.namespaces).toEqual(["(cluster-wide)", "demo"]);
  });
});

describe("describeOutcome", () => {
  const r = (name: string, ns: string | null = "demo") => report(name, name, ns);
  const empty = { requested: [], gone: [], failed: [] };

  it("says the rescan was requested, with how long it usually takes", () => {
    expect(describeOutcome({ ...empty, requested: [r("a")] })).toEqual([
      { tone: "ok", text: "Rescan requested for 1 workload. The new report usually appears within 2 to 5 minutes." },
    ]);
    expect(describeOutcome({ ...empty, requested: [r("a"), r("b")] })[0].text).toContain("2 workloads");
    expect(describeOutcome({ ...empty, requested: [r("a"), r("b")] })[0].text).toContain("new reports usually appear");
  });

  it("explains a forbidden answer with the permission to ask for", () => {
    const [m] = describeOutcome({ ...empty, failed: [{ item: r("a"), reason: "forbidden", message: "x" }] });
    expect(m.tone).toBe("error");
    expect(m.text).toContain("Forbidden");
    expect(m.text).toContain("VulnerabilityReport");
    expect(m.text).toContain("namespace demo");
    expect(m.text).toContain("delete");
  });

  it("names cluster-wide reports without a namespace", () => {
    const [m] = describeOutcome({ ...empty, failed: [{ item: r("a", null), reason: "forbidden", message: "x" }] });
    expect(m.text).not.toContain("namespace");
  });

  it("shows the cluster's own message for any other failure", () => {
    const [m] = describeOutcome({
      ...empty,
      failed: [{ item: r("a"), reason: "other", message: "connection refused" }],
    });
    expect(m).toEqual({ tone: "error", text: "Could not delete 1 report: connection refused" });
  });

  it("says nothing was changed when every report was already gone", () => {
    expect(describeOutcome({ ...empty, gone: [r("a")] })).toEqual([
      {
        tone: "info",
        text: "Nothing was changed. The report was already gone; the operator may be rescanning it now.",
      },
    ]);
  });

  it("reports a mixed result as one message per outcome", () => {
    const messages = describeOutcome({
      requested: [r("a")],
      gone: [r("b")],
      failed: [{ item: r("c"), reason: "other", message: "boom" }],
    });
    expect(messages.map((m) => m.tone)).toEqual(["ok", "error"]);
  });
});

describe("confirmPlan for one workload", () => {
  const workload = { kind: "Deployment", name: "web", namespace: "demo" };
  it("needs no typing even though several reports are deleted, because it is one workload", () => {
    const plan = confirmPlan([report("a", "1"), report("b", "2"), report("c", "3")], "dev-cluster", workload);
    expect(plan).toMatchObject({ count: 3, needsTyping: false, workload });
    expect(isConfirmed(plan, "")).toBe(true);
  });
  it("is unchanged without a workload", () => {
    expect(confirmPlan([report("a", "1"), report("b", "2")], "c").workload).toBeUndefined();
  });
});
