import { describe, expect, it } from "vitest";
import {
  type Activity,
  describeScan,
  explainFailure,
  type JobLike,
  observe,
  type PodLike,
  stateOf,
  usesScanJob,
} from "./scan-status-model";

const labels = (kind = "Deployment", name = "web", namespace = "demo") => ({
  "app.kubernetes.io/managed-by": "trivy-operator",
  "trivy-operator.resource.kind": kind,
  "trivy-operator.resource.name": name,
  "trivy-operator.resource.namespace": namespace,
});
const job = (name: string, over: Partial<JobLike["status"]> = {}, l = labels()): JobLike => ({
  metadata: { name, namespace: "scans", labels: l },
  status: { active: 1, ...over },
});
const pod = (jobName: string, status: PodLike["status"], l = labels()): PodLike => ({
  metadata: { name: `${jobName}-x1`, namespace: "scans", labels: { ...l, "job-name": jobName } },
  status,
});
const report = (kind = "VulnerabilityReport", l: Record<string, string> = labels()) => ({
  kind,
  metadata: { name: "r", namespace: "demo", uid: "u", labels: l },
});
const none: Activity = { jobs: [], pods: [] };

const DNS_MESSAGE = [
  "2026-10-10T09:20:53Z\tFATAL\tFatal error\timage scan error: unable to find the specified image",
  "\t* docker error: unable to inspect the image: dial unix /var/run/docker.sock: connect: no such file or directory",
  "\t* containerd error: containerd socket not found: /run/containerd/containerd.sock",
  "\t* podman error: unable to initialize Podman client: no podman socket found",
  '\t* remote error: Get "https://registry.invalid/v2/": dial tcp: lookup registry.invalid on dns.example:53: no such host',
].join("\n");

describe("usesScanJob", () => {
  it("is true for the reports a scan Job makes, and false for those the operator computes itself", () => {
    for (const kind of ["VulnerabilityReport", "ExposedSecretReport", "SbomReport"])
      expect(usesScanJob(kind), kind).toBe(true);
    for (const kind of [
      "ConfigAuditReport",
      "RbacAssessmentReport",
      "InfraAssessmentReport",
      "ClusterRbacAssessmentReport",
    ]) {
      expect(usesScanJob(kind), kind).toBe(false);
    }
  });
});

describe("stateOf", () => {
  it("is nothing for a report no Job makes", () => {
    expect(stateOf(report("ConfigAuditReport"), none, false)).toBeUndefined();
  });

  it("is queued while no Job exists, saying how many scans are running", () => {
    const busy: Activity = {
      jobs: [job("a", {}, labels("Deployment", "other")), job("b", {}, labels("Deployment", "more"))],
      pods: [],
    };
    expect(stateOf(report(), busy, false)).toEqual({ kind: "queued", running: 2 });
    expect(stateOf(report(), none, false)).toEqual({ kind: "queued", running: 0 });
  });

  it("matches a Job to the workload by the labels the operator puts on both", () => {
    const mine = job("mine");
    const other = job("other", {}, labels("Deployment", "web2"));
    const pods = [pod("mine", { phase: "Pending", initContainerStatuses: [{ name: "init", state: { running: {} } }] })];
    expect(stateOf(report(), { jobs: [other, mine], pods }, false)).toEqual({ kind: "starting" });
  });

  it("is starting while the pod prepares, and scanning once the scanner container runs", () => {
    const starting = [pod("j", { phase: "Pending", initContainerStatuses: [{ name: "i", state: { running: {} } }] })];
    expect(stateOf(report(), { jobs: [job("j")], pods: starting }, false)).toEqual({ kind: "starting" });
    const scanning = [
      pod("j", {
        phase: "Running",
        initContainerStatuses: [{ name: "i", state: { terminated: { exitCode: 0 } } }],
        containerStatuses: [{ name: "c", state: { running: {} } }],
      }),
    ];
    expect(stateOf(report(), { jobs: [job("j")], pods: scanning }, false)).toEqual({ kind: "scanning" });
  });

  it("is starting for a Job whose pod does not exist yet", () => {
    expect(stateOf(report(), { jobs: [job("j")], pods: [] }, false)).toEqual({ kind: "starting" });
  });

  it("reads a failure from the scan pod while it is still there, with the registry's answer", () => {
    const failed = pod("j", {
      phase: "Failed",
      containerStatuses: [{ name: "c", state: { terminated: { exitCode: 1, reason: "Error", message: DNS_MESSAGE } } }],
    });
    const state = stateOf(report(), { jobs: [job("j")], pods: [failed] }, false);
    expect(state).toMatchObject({
      kind: "failed",
      reason: "Cannot reach the image registry: the name does not resolve",
    });
    expect((state as { detail: string }).detail).toContain("no such host");
  });

  it("reads an out-of-memory kill and a scanner image that cannot be pulled", () => {
    const oom = pod("j", {
      phase: "Failed",
      containerStatuses: [{ name: "c", state: { terminated: { exitCode: 137, reason: "OOMKilled" } } }],
    });
    expect(stateOf(report(), { jobs: [job("j")], pods: [oom] }, false)).toMatchObject({
      kind: "failed",
      reason: "The scan ran out of memory (OOMKilled)",
    });
    const pull = pod("j", {
      phase: "Pending",
      initContainerStatuses: [
        { name: "i", state: { waiting: { reason: "ImagePullBackOff", message: "Back-off pulling image" } } },
      ],
    });
    expect(stateOf(report(), { jobs: [job("j")], pods: [pull] }, false)).toMatchObject({
      kind: "failed",
      reason: "The scanner image could not be pulled (ImagePullBackOff)",
    });
  });

  it("reads a Job that failed without a pod to explain it", () => {
    const failed = job("j", {
      active: 0,
      failed: 1,
      conditions: [
        {
          type: "Failed",
          status: "True",
          reason: "DeadlineExceeded",
          message: "Job was active longer than specified deadline",
        },
      ],
    });
    expect(stateOf(report(), { jobs: [failed], pods: [] }, false)).toMatchObject({
      kind: "failed",
      reason: "The scan took longer than the operator allows (DeadlineExceeded)",
    });
  });

  it("is ended when a Job was seen, is gone, and no report came", () => {
    expect(stateOf(report(), none, true)).toEqual({ kind: "ended" });
  });
});

describe("explainFailure", () => {
  const remote = (text: string) =>
    `\t* docker error: nope\n\t* containerd error: containerd socket not found\n\t* remote error: ${text}`;
  it("gives the registry's answer, ignoring the docker/containerd/podman noise every scan prints", () => {
    expect(explainFailure(DNS_MESSAGE).reason).toBe("Cannot reach the image registry: the name does not resolve");
    expect(
      explainFailure(remote("GET https://r.example/v2/a/manifests/1: UNAUTHORIZED: authentication required")).reason,
    ).toBe("The registry refused the credentials");
    expect(
      explainFailure(remote("GET https://r.example/v2/a/manifests/9: MANIFEST_UNKNOWN: manifest unknown")).reason,
    ).toBe("The image or tag is not in the registry");
    expect(explainFailure(remote("GET https://r.example/v2/: TOOMANYREQUESTS: rate limit")).reason).toBe(
      "The registry's rate limit was reached",
    );
    expect(
      explainFailure(remote('Get "https://r.example/v2/": x509: certificate signed by unknown authority')).reason,
    ).toBe("The registry's certificate is not trusted");
    expect(explainFailure(remote('Get "https://r.example/v2/": context deadline exceeded')).reason).toBe(
      "The registry did not answer in time",
    );
  });
  it("falls back to the last error line, trimmed, and to the exit code", () => {
    expect(explainFailure("2026-10-10T09:20:53Z\tFATAL\tFatal error\tsomething odd happened").reason).toBe(
      "something odd happened",
    );
    expect(explainFailure("nothing useful", 2).reason).toBe("The scan exited with code 2");
    expect(explainFailure(undefined).reason).toBe("The scan failed");
  });
  it("keeps the whole text as detail, capped", () => {
    expect(explainFailure("x".repeat(5000)).detail.length).toBeLessThanOrEqual(1200);
  });
});

describe("describeScan", () => {
  const pending = (scan?: object, requestedAt = 0) => ({ key: "k", item: report(), uid: "u", requestedAt, scan });
  const MIN = 60_000;

  it("says Rescanning with the elapsed time for a report no Job makes", () => {
    expect(describeScan(pending(), 2 * MIN)).toEqual({ tone: "busy", text: "Rescanning · 2m" });
  });
  it("words each state of a scan", () => {
    expect(describeScan(pending({ state: { kind: "queued", running: 2 } }), 30_000)).toMatchObject({
      tone: "busy",
      text: "Queued · <1m",
      title: "2 scans are running. The operator limits how many run at once, so this one waits for a free slot.",
    });
    expect(describeScan(pending({ state: { kind: "queued", running: 0 } }), 30_000).title).toContain(
      "no scan is running",
    );
    expect(describeScan(pending({ state: { kind: "starting" } }), MIN).text).toBe("Starting scan · 1m");
    expect(describeScan(pending({ state: { kind: "scanning" } }), 3 * MIN).text).toBe("Scanning · 3m");
    expect(describeScan(pending({ state: { kind: "ended" } }), MIN)).toMatchObject({
      tone: "warn",
      text: "Scan ended without a report",
    });
  });
  it("shows a failure with its reason, and keeps it as the reason after ten minutes", () => {
    const failed = {
      state: { kind: "failed", reason: "The image or tag is not in the registry", detail: "full text" },
    };
    expect(describeScan(pending(failed), MIN)).toEqual({
      tone: "error",
      text: "Scan failed",
      note: "The image or tag is not in the registry",
      title: "full text",
    });
    const stale = describeScan(pending(failed), 11 * MIN);
    expect(stale.text).toBe("No new report after 10m");
    expect(stale.note).toBe("The image or tag is not in the registry");
    expect(stale.title).toContain("full text");
  });
  it("says there is no new report after ten minutes whatever the state", () => {
    expect(describeScan(pending({ state: { kind: "scanning" } }), 10 * MIN)).toMatchObject({
      tone: "warn",
      text: "No new report after 10m",
    });
  });
});

describe("observe", () => {
  const failedPod = (jobName: string) =>
    pod(jobName, {
      phase: "Failed",
      containerStatuses: [{ name: "c", state: { terminated: { exitCode: 1, message: DNS_MESSAGE } } }],
    });
  const running = (jobName: string) =>
    pod(jobName, { phase: "Running", containerStatuses: [{ name: "c", state: { running: {} } }] });

  it("remembers that a Job was seen, so its disappearance reads as ended and not as queued", () => {
    const first = observe(report(), { jobs: [job("j")], pods: [running("j")] });
    expect(first).toMatchObject({ seen: true, state: { kind: "scanning" } });
    expect(observe(report(), none, first).state).toEqual({ kind: "ended" });
  });

  it("is queued, unseen, while the operator has not started", () => {
    expect(observe(report(), none)).toMatchObject({ seen: false, state: { kind: "queued" } });
  });

  it("keeps a failure after the failed Job is removed", () => {
    const failed = observe(report(), { jobs: [job("j")], pods: [failedPod("j")] });
    expect(failed.state?.kind).toBe("failed");
    const later = observe(report(), none, failed);
    expect(later.state?.kind).toBe("failed");
    expect(later.failedJob).toBe("j");
  });

  it("replaces the failure when the operator tries again with a new Job", () => {
    const failed = observe(report(), { jobs: [job("j")], pods: [failedPod("j")] });
    const retry = observe(report(), { jobs: [job("j2")], pods: [running("j2")] }, failed);
    expect(retry.state).toEqual({ kind: "scanning" });
  });

  it("does not let the same, still-listed failed Job flip back to a live state", () => {
    const failed = observe(report(), { jobs: [job("j")], pods: [failedPod("j")] });
    const same = observe(report(), { jobs: [job("j")], pods: [] }, failed);
    expect(same.state?.kind).toBe("failed");
  });

  it("leaves a report no Job makes untouched", () => {
    expect(observe(report("ConfigAuditReport"), none, {})).toEqual({});
  });
});
