// Which reports belong to a workload that has its own drawer.
//
// The operator scans the controller a pod belongs to, and for a Deployment that is its
// ReplicaSet (`<deployment>-<pod-template-hash>`), for a CronJob its Job
// (`<cronjob>-<scheduled minute>`). A drawer for the Deployment or CronJob therefore
// matches those children by name.

import { resourceOf } from "../api/trivy/report-model";

export interface WorkloadTarget {
  kind: string;
  name: string;
  namespace: string;
}

interface ReportLike {
  metadata?: Parameters<typeof resourceOf>[0];
}

const escape = (text: string) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export function reportBelongsTo(report: ReportLike, target: WorkloadTarget): boolean {
  const ref = resourceOf(report.metadata);
  if (!ref.name || (ref.namespace && target.namespace && ref.namespace !== target.namespace)) return false;
  if (ref.kind === target.kind && ref.name === target.name) return true;
  if (target.kind === "Deployment" && ref.kind === "ReplicaSet") {
    return new RegExp(`^${escape(target.name)}-[a-z0-9]{5,10}$`).test(ref.name);
  }
  if (target.kind === "CronJob" && ref.kind === "Job") {
    return new RegExp(`^${escape(target.name)}-\\d+$`).test(ref.name);
  }
  return false;
}

/** The targets a drawer should match: the object itself and, for a Pod, the controller that owns it. */
export function targetsFor(object: {
  kind?: string;
  metadata: {
    name?: string;
    namespace?: string;
    ownerReferences?: { kind?: string; name?: string; controller?: boolean }[];
  };
}): WorkloadTarget[] {
  const namespace = object.metadata.namespace ?? "";
  const targets: WorkloadTarget[] = [{ kind: object.kind ?? "", name: object.metadata.name ?? "", namespace }];
  if (object.kind === "Pod") {
    const owner = object.metadata.ownerReferences?.find((o) => o.controller) ?? object.metadata.ownerReferences?.[0];
    if (owner?.kind && owner.name) targets.push({ kind: owner.kind, name: owner.name, namespace });
  }
  return targets;
}

export function reportsFor<T extends ReportLike>(reports: T[], targets: WorkloadTarget[]): T[] {
  return reports.filter((report) => targets.some((target) => reportBelongsTo(report, target)));
}

/** The container names a workload or Pod declares, so a container nobody scanned can be shown as such. */
export function containersOf(object: { kind?: string; spec?: any }): string[] {
  const spec = object.spec ?? {};
  const podSpec =
    object.kind === "Pod"
      ? spec
      : object.kind === "CronJob"
        ? spec.jobTemplate?.spec?.template?.spec
        : spec.template?.spec;
  return ((podSpec?.containers ?? []) as { name?: string }[]).map((c) => c.name).filter((n): n is string => Boolean(n));
}

export interface WorkloadCards<R> {
  containers: { name: string; vulnerabilities?: R; secrets?: R; scanned: boolean }[];
  configs: R[];
}

/**
 * What the Trivy Operator section shows: one card per container (its vulnerability and secret reports,
 * or "not scanned yet" when it is declared but has none) and the configuration reports.
 */
export function workloadCards<R extends ReportLike>(
  declared: string[],
  reports: { vulnerabilities: R[]; secrets: R[]; configs: R[] },
): WorkloadCards<R> {
  const containerOf = (r: R) => resourceOf(r.metadata).container ?? "";
  const names = [
    ...new Set([...declared, ...reports.vulnerabilities.map(containerOf), ...reports.secrets.map(containerOf)]),
  ].filter(Boolean);
  return {
    containers: names.map((name) => {
      const vulnerabilities = reports.vulnerabilities.find((r) => containerOf(r) === name);
      const secrets = reports.secrets.find((r) => containerOf(r) === name);
      return { name, vulnerabilities, secrets, scanned: Boolean(vulnerabilities) };
    }),
    configs: reports.configs,
  };
}
