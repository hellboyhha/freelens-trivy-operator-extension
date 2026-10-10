// What the operator is doing about a report that was deleted for a rescan, read from its scan Jobs.
//
// Vulnerability, secret and SBOM reports are made by a Job per workload in the operator's namespace.
// The operator runs a few at a time, so a deleted report first waits for a free slot, then its Job
// prepares and scans, and the new report appears. A failed Job is removed within seconds and leaves
// nothing in the cluster but the operator's own log, so a failure is only seen if it is read while
// it lasts: the tracker polls every few seconds and keeps what it saw.

import { elapsedText, type Pending, type ReportLike, STALE_AFTER_MS } from "./rescan-model";

/** Every Job and scan pod the operator made carry this, and the same labels as the report. */
export const OPERATOR_LABEL_SELECTOR = "app.kubernetes.io/managed-by=trivy-operator";

const RESOURCE = {
  kind: "trivy-operator.resource.kind",
  name: "trivy-operator.resource.name",
  namespace: "trivy-operator.resource.namespace",
};

type Labels = Record<string, string>;

interface ContainerStatus {
  name?: string;
  state?: {
    running?: object;
    waiting?: { reason?: string; message?: string };
    terminated?: { exitCode?: number; reason?: string; message?: string };
  };
}

export interface JobLike {
  metadata: { name?: string; namespace?: string; labels?: Labels };
  status?: {
    active?: number;
    failed?: number;
    succeeded?: number;
    conditions?: { type: string; status: string; reason?: string; message?: string }[];
  };
}

export interface PodLike {
  metadata: { name?: string; namespace?: string; labels?: Labels };
  status?: { phase?: string; initContainerStatuses?: ContainerStatus[]; containerStatuses?: ContainerStatus[] };
}

export interface Activity {
  jobs: JobLike[];
  pods: PodLike[];
}

export type ScanState =
  | { kind: "queued"; running: number }
  | { kind: "starting" }
  | { kind: "scanning" }
  | { kind: "failed"; reason: string; detail: string }
  | { kind: "ended" };

/** What the tracker remembers about one waiting report between polls. */
export interface ScanProgress {
  state?: ScanState;
  /** A Job for this workload has been seen: if it is gone with no report, the scan ended. */
  seen?: boolean;
  /** The name of the Job whose failure is shown, so a later, different Job replaces it. */
  failedJob?: string;
}

const JOB_KINDS = new Set(["VulnerabilityReport", "ExposedSecretReport", "SbomReport"]);

/** The reports a scan Job makes; the others (configuration, RBAC, infra) are computed by the operator itself. */
export const usesScanJob = (kind?: string): boolean => JOB_KINDS.has(kind ?? "");

const MAX_DETAIL = 1200;

/** The registry's own answer is the line after "remote error:"; the lines before it are noise every scan prints. */
const REASONS: [RegExp, string][] = [
  [/no such host|lookup .+ on .+:53/i, "Cannot reach the image registry: the name does not resolve"],
  [/unauthorized|authentication required|denied|\b401\b|\b403\b/i, "The registry refused the credentials"],
  [/manifest unknown|name unknown|not found|\b404\b/i, "The image or tag is not in the registry"],
  [/toomanyrequests|rate limit/i, "The registry's rate limit was reached"],
  [/x509|certificate/i, "The registry's certificate is not trusted"],
  [/deadline exceeded|i\/o timeout|timed out|timeout/i, "The registry did not answer in time"],
  [/connection refused/i, "The registry refused the connection"],
];

export function explainFailure(message?: string, exitCode?: number): { reason: string; detail: string } {
  const text = (message ?? "").trim();
  // The end of a long message holds the cause; start at a line boundary so the text does not open mid-word.
  const tail = text.length > MAX_DETAIL ? text.slice(-MAX_DETAIL) : text;
  const detail = tail === text ? text : tail.slice(tail.indexOf("\n") + 1);
  const remote = /remote error: ([^\n]*)/.exec(text)?.[1];
  const core = remote ?? text;
  for (const [pattern, reason] of REASONS) if (pattern.test(core)) return { reason, detail };

  const line = text
    .split("\n")
    .reverse()
    .find((l) => /\b(error|fatal|failed)\b/i.test(l));
  const cleaned = line
    ?.replace(/^\s*\d{4}-\d\d-\d\dT[\d:.]+Z\s*/, "")
    .replace(/^\s*(FATAL|ERROR|WARN)\s*(Fatal error)?\s*/i, "")
    .replace(/^[\s*]+/, "")
    .trim();
  if (cleaned) return { reason: cleaned.slice(0, 160), detail };
  if (exitCode !== undefined && exitCode !== 0) return { reason: `The scan exited with code ${exitCode}`, detail };
  return { reason: "The scan failed", detail };
}

const WAITING_FAILURES = new Set([
  "ImagePullBackOff",
  "ErrImagePull",
  "CrashLoopBackOff",
  "CreateContainerConfigError",
  "InvalidImageName",
]);

const JOB_FAILURES: Record<string, string> = {
  DeadlineExceeded: "The scan took longer than the operator allows (DeadlineExceeded)",
  BackoffLimitExceeded: "The scan failed and was not retried (BackoffLimitExceeded)",
};

function failureOf(job: JobLike, pods: PodLike[]): { reason: string; detail: string } | undefined {
  for (const pod of pods) {
    const statuses = [...(pod.status?.initContainerStatuses ?? []), ...(pod.status?.containerStatuses ?? [])];
    for (const status of statuses) {
      const waiting = status.state?.waiting;
      if (waiting?.reason && WAITING_FAILURES.has(waiting.reason)) {
        const isInit = (pod.status?.initContainerStatuses ?? []).includes(status);
        return {
          reason: isInit
            ? `The scanner image could not be pulled (${waiting.reason})`
            : `The scan could not start (${waiting.reason})`,
          detail: waiting.message ?? waiting.reason,
        };
      }
      const ended = status.state?.terminated;
      if (ended && ended.exitCode !== 0) {
        if (ended.reason === "OOMKilled") {
          return {
            reason: "The scan ran out of memory (OOMKilled)",
            detail: "The scan container was killed for using more memory than its limit.",
          };
        }
        return explainFailure(ended.message, ended.exitCode);
      }
    }
  }
  const condition = job.status?.conditions?.find((c) => c.type === "Failed" && c.status === "True");
  if (condition) {
    return {
      reason: JOB_FAILURES[condition.reason ?? ""] ?? condition.message ?? "The scan failed",
      detail: [condition.reason, condition.message].filter(Boolean).join(": "),
    };
  }
  return undefined;
}

function isRunning(pods: PodLike[]): boolean {
  return pods.some((p) => (p.status?.containerStatuses ?? []).some((c) => c.state?.running));
}

/**
 * Where the scan of this report's workload stands: undefined for a report no Job makes. `seen` says a
 * Job for it was observed before, which turns "no Job" from "queued" into "ended".
 */
export function stateOf(
  item: ReportLike & { metadata: { labels?: Labels } },
  activity: Activity,
  seen: boolean,
): ScanState | undefined {
  if (!usesScanJob(item.kind)) return undefined;
  const labels = item.metadata.labels ?? {};
  const mine = (l?: Labels) =>
    !!l &&
    l[RESOURCE.kind] === labels[RESOURCE.kind] &&
    l[RESOURCE.name] === labels[RESOURCE.name] &&
    l[RESOURCE.namespace] === labels[RESOURCE.namespace];

  const jobs = activity.jobs.filter((j) => mine(j.metadata.labels));
  if (jobs.length === 0) {
    if (seen) return { kind: "ended" };
    return { kind: "queued", running: activity.jobs.filter((j) => (j.status?.active ?? 0) > 0).length };
  }
  // Several Jobs for one workload are rare; the newest decision is the first failure, else the first live one.
  let live: ScanState = { kind: "starting" };
  for (const job of jobs) {
    const pods = activity.pods.filter((p) => p.metadata.labels?.["job-name"] === job.metadata.name);
    const failure = failureOf(job, pods);
    if (failure) return { kind: "failed", ...failure };
    if (isRunning(pods)) live = { kind: "scanning" };
  }
  return live;
}

/** The job name behind a state, so a failure can be tied to it. */
export function jobNameFor(item: { metadata: { labels?: Labels } }, activity: Activity): string | undefined {
  const labels = item.metadata.labels ?? {};
  return activity.jobs.find(
    (j) =>
      j.metadata.labels?.[RESOURCE.kind] === labels[RESOURCE.kind] &&
      j.metadata.labels?.[RESOURCE.name] === labels[RESOURCE.name] &&
      j.metadata.labels?.[RESOURCE.namespace] === labels[RESOURCE.namespace],
  )?.metadata.name;
}

/**
 * Folds one poll into what is remembered about a waiting report. A failure stays shown after the Job is
 * removed; a different Job (the operator trying again) replaces it.
 */
export function observe(
  item: ReportLike & { metadata: { labels?: Labels } },
  activity: Activity,
  before: ScanProgress = {},
): ScanProgress {
  const state = stateOf(item, activity, !!before.seen);
  if (!state) return before;
  const job = jobNameFor(item, activity);
  const seen = !!before.seen || state.kind === "starting" || state.kind === "scanning" || state.kind === "failed";

  if (state.kind === "failed") return { state, seen, failedJob: job };
  // A failure stays until a different Job shows up in a live state.
  if (
    before.state?.kind === "failed" &&
    (state.kind === "ended" || state.kind === "queued" || job === before.failedJob)
  ) {
    return { ...before, seen };
  }
  return { state, seen, failedJob: undefined };
}

export type Tone = "busy" | "warn" | "error";

export interface ScanText {
  tone: Tone;
  text: string;
  /** A second, smaller line: the reason of a failure. */
  note?: string;
  title?: string;
}

/** The words of the row's pill: what is happening, how long it has been, and why it failed. */
export function describeScan(pending: Pending<ReportLike>, now: number): ScanText {
  const elapsed = now - pending.requestedAt;
  const state = pending.scan?.state;

  if (elapsed >= STALE_AFTER_MS) {
    const failed = state?.kind === "failed" ? state : undefined;
    return {
      tone: "warn",
      text: `No new report after ${STALE_AFTER_MS / 60_000}m`,
      ...(failed ? { note: failed.reason } : {}),
      title: failed?.detail || "The operator has not written a new report. Is it running?",
    };
  }
  const time = elapsedText(elapsed);
  switch (state?.kind) {
    case "queued":
      return {
        tone: "busy",
        text: `Queued · ${time}`,
        title:
          state.running > 0
            ? `${state.running} ${state.running === 1 ? "scan is" : "scans are"} running. The operator limits how many run at once, so this one waits for a free slot.`
            : "The operator has not started this scan yet; no scan is running.",
      };
    case "starting":
      return {
        tone: "busy",
        text: `Starting scan · ${time}`,
        title: "The scan pod is preparing: pulling the scanner and the vulnerability database.",
      };
    case "scanning":
      return { tone: "busy", text: `Scanning · ${time}` };
    case "failed":
      return { tone: "error", text: "Scan failed", note: state.reason, title: state.detail };
    case "ended":
      return {
        tone: "warn",
        text: "Scan ended without a report",
        title: "The scan Job finished or was removed but no report appeared. The operator's log has the reason.",
      };
    default:
      return { tone: "busy", text: `Rescanning · ${time}` };
  }
}
