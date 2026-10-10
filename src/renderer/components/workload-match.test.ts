import { describe, expect, it } from "vitest";
import { containersOf, reportBelongsTo, reportsFor, targetsFor, workloadCards } from "./workload-match";

const report = (kind: string, name: string, namespace = "demo") => ({
  metadata: {
    namespace,
    labels: {
      "trivy-operator.resource.kind": kind,
      "trivy-operator.resource.name": name,
      "trivy-operator.resource.namespace": namespace,
    },
  },
});

describe("reportBelongsTo", () => {
  it("matches the same kind and name", () => {
    expect(reportBelongsTo(report("StatefulSet", "db"), { kind: "StatefulSet", name: "db", namespace: "demo" })).toBe(
      true,
    );
  });
  it("does not cross namespaces", () => {
    expect(
      reportBelongsTo(report("StatefulSet", "db", "other"), { kind: "StatefulSet", name: "db", namespace: "demo" }),
    ).toBe(false);
  });
  it("matches a Deployment's ReplicaSets but not a neighbour's", () => {
    const target = { kind: "Deployment", name: "web", namespace: "demo" };
    expect(reportBelongsTo(report("ReplicaSet", "web-5d8f7c9b6"), target)).toBe(true);
    expect(reportBelongsTo(report("ReplicaSet", "web-api-5d8f7c9b6"), target)).toBe(false);
    expect(reportBelongsTo(report("ReplicaSet", "webby-5d8f7c9b6"), target)).toBe(false);
  });
  it("matches a CronJob's Jobs", () => {
    const target = { kind: "CronJob", name: "backup", namespace: "demo" };
    expect(reportBelongsTo(report("Job", "backup-29012345"), target)).toBe(true);
    expect(reportBelongsTo(report("Job", "backup-old-29012345"), target)).toBe(false);
  });
  it("ignores reports whose name is unknown", () => {
    expect(
      reportBelongsTo(
        { metadata: { labels: { "trivy-operator.resource.kind": "Role" } } },
        { kind: "Role", name: "", namespace: "" },
      ),
    ).toBe(false);
  });
  it("escapes regular expression characters in names", () => {
    expect(
      reportBelongsTo(report("ReplicaSet", "web-5d8f7c9b6"), { kind: "Deployment", name: "we.", namespace: "demo" }),
    ).toBe(false);
  });
});

describe("targetsFor", () => {
  it("adds the controller of a Pod", () => {
    const targets = targetsFor({
      kind: "Pod",
      metadata: {
        name: "web-5d8f7c9b6-x",
        namespace: "demo",
        ownerReferences: [{ kind: "ReplicaSet", name: "web-5d8f7c9b6", controller: true }],
      },
    });
    expect(targets).toEqual([
      { kind: "Pod", name: "web-5d8f7c9b6-x", namespace: "demo" },
      { kind: "ReplicaSet", name: "web-5d8f7c9b6", namespace: "demo" },
    ]);
  });
  it("is just the object for other kinds", () => {
    expect(targetsFor({ kind: "Deployment", metadata: { name: "web", namespace: "demo" } })).toHaveLength(1);
  });
});

describe("reportsFor", () => {
  it("filters a list", () => {
    const reports = [report("ReplicaSet", "web-5d8f7c9b6"), report("ReplicaSet", "other-5d8f7c9b6")];
    expect(reportsFor(reports, [{ kind: "Deployment", name: "web", namespace: "demo" }])).toEqual([reports[0]]);
  });
});

describe("containersOf", () => {
  it("reads the containers of each workload shape", () => {
    const containers = [{ name: "web" }, { name: "sidecar" }];
    expect(containersOf({ kind: "Pod", spec: { containers } })).toEqual(["web", "sidecar"]);
    expect(containersOf({ kind: "Deployment", spec: { template: { spec: { containers } } } })).toEqual([
      "web",
      "sidecar",
    ]);
    expect(
      containersOf({ kind: "CronJob", spec: { jobTemplate: { spec: { template: { spec: { containers } } } } } }),
    ).toEqual(["web", "sidecar"]);
    expect(containersOf({ kind: "Deployment" })).toEqual([]);
  });
});

describe("workloadCards", () => {
  const rep = (container: string) => ({ metadata: { labels: { "trivy-operator.container.name": container } } });
  it("makes one card per container and marks the unscanned ones", () => {
    const web = rep("web");
    const cards = workloadCards(["web", "job"], { vulnerabilities: [web], secrets: [], configs: [] });
    expect(cards.containers).toEqual([
      { name: "web", vulnerabilities: web, secrets: undefined, scanned: true },
      { name: "job", vulnerabilities: undefined, secrets: undefined, scanned: false },
    ]);
  });
  it("adds containers that have a report but are not in the spec, and attaches secrets to their container", () => {
    const secret = rep("web");
    const cards = workloadCards([], { vulnerabilities: [rep("web"), rep("extra")], secrets: [secret], configs: [] });
    expect(cards.containers.map((c) => c.name)).toEqual(["web", "extra"]);
    expect(cards.containers[0].secrets).toBe(secret);
  });
});
