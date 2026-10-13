// The columns the report lists are built from. A list page picks the ones its kind has.

import { Renderer } from "@freelensapp/extensions";
import {
  countFixable,
  matchPackages,
  resourceLabel,
  resourceOf,
  severityCounts,
  severityWeight,
  sortedSecrets,
  totalCount,
  versionKey,
  worstIssue,
} from "../api/trivy/report-model";
import { formatAge } from "./format";
import styles from "./report-list.module.scss";
import { Fixable, ImageName, Muted, SeverityCell, TwoLine } from "./ui";

import type {
  Artifact,
  Check,
  ExposedSecret,
  SbomComponent,
  SeveritySummary,
  Vulnerability,
} from "../api/trivy/common";

const {
  Component: { WithTooltip },
} = Renderer;

export interface ReportData {
  summary?: SeveritySummary;
  updateTimestamp?: string;
  artifact?: Artifact;
  vulnerabilities?: Vulnerability[];
  checks?: Check[];
  secrets?: ExposedSecret[];
  registry?: { server?: string };
  components?: { bomFormat?: string; specVersion?: string; components?: SbomComponent[] };
}

/** What every report kind has in common; the compliance report keeps its data elsewhere. */
export type ReportObject = Renderer.K8sApi.LensExtensionKubeObject<any, any, any> & { report?: ReportData };

/** What a page knows beyond the object, for the columns that depend on it. */
export interface ListContext {
  /** The package the user is looking for; empty when not searching. */
  query: string;
}

export interface Column<T> {
  id: string;
  title: string;
  className?: string;
  sort?: (object: T, context: ListContext) => string | number;
  render: (object: T, context: ListContext) => React.ReactNode;
  search?: (object: T) => string[];
  /** The column is only shown while this holds. */
  when?: (context: ListContext) => boolean;
}

function resourceRef(object: ReportObject) {
  const ref = resourceOf(object.metadata);
  return ref.name ? ref : { ...ref, name: object.getName() };
}

/** The workload name over `namespace · Kind · container`. */
export function workloadColumn<T extends ReportObject>(): Column<T> {
  return {
    id: "workload",
    title: "Workload",
    className: styles.workload,
    sort: (o) => resourceLabel(resourceRef(o)),
    render: (o) => {
      const ref = resourceRef(o);
      return (
        <TwoLine title={ref.name} subtitle={[ref.namespace, ref.kind, ref.container].filter(Boolean).join(" · ")} />
      );
    },
    search: (o) => [resourceLabel(resourceRef(o)), resourceRef(o).namespace, resourceRef(o).container ?? ""],
  };
}

export function imageColumn<T extends ReportObject>(): Column<T> {
  return {
    id: "image",
    title: "Image",
    className: styles.image,
    sort: (o) => `${o.report?.artifact?.repository ?? ""}:${o.report?.artifact?.tag ?? ""}`,
    render: (o) => (
      <ImageName
        repository={o.report?.artifact?.repository}
        tag={o.report?.artifact?.tag}
        title={[o.report?.registry?.server, o.report?.artifact?.digest].filter(Boolean).join("\n")}
      />
    ),
    search: (o) => [
      o.report?.artifact?.repository ?? "",
      o.report?.artifact?.tag ?? "",
      o.report?.registry?.server ?? "",
    ],
  };
}

/** One column with the bar and the four counts; sorts the worst reports first. */
export function severityColumn<T>(summaryOf: (object: T) => SeveritySummary | undefined): Column<T> {
  return {
    id: "severity",
    title: "Severity",
    className: styles.severityCell,
    sort: (o) => severityWeight(severityCounts(summaryOf(o))),
    render: (o) => <SeverityCell counts={severityCounts(summaryOf(o))} />,
  };
}

/** When the operator last scanned the object, as an age. */
export function scannedColumn<T extends ReportObject>(): Column<T> {
  return {
    id: "scanned",
    title: "Scanned",
    className: styles.number,
    sort: (o) => Date.parse(o.report?.updateTimestamp ?? "") || 0,
    render: (o) =>
      o.report?.updateTimestamp ? <Muted>{formatAge(o.report.updateTimestamp)} ago</Muted> : <Muted>N/A</Muted>,
  };
}

export function fixableColumn<T extends ReportObject>(): Column<T> {
  return {
    id: "fixable",
    title: "Fixable",
    className: styles.number,
    sort: (o) => countFixable(o.report?.vulnerabilities),
    render: (o) => {
      const n = countFixable(o.report?.vulnerabilities);
      return n > 0 ? <Fixable>{n}</Fixable> : <Muted>–</Muted>;
    },
  };
}

/** The most severe failed check, and how many more failed. */
export function worstIssueColumn<T extends ReportObject>(): Column<T> {
  return {
    id: "issue",
    title: "Worst issue",
    className: styles.issue,
    sort: (o) => totalCount(severityCounts(o.report?.summary)),
    render: (o) => {
      const issue = worstIssue(o.report?.checks);
      if (!issue) return <Muted>no failed checks</Muted>;
      return (
        <WithTooltip>
          {issue.title}
          {issue.more > 0 ? <Muted> +{issue.more} more</Muted> : null}
        </WithTooltip>
      );
    },
    search: (o) => (o.report?.checks ?? []).filter((c) => c.success === false).map((c) => `${c.title} ${c.checkID}`),
  };
}

/** The most severe secret rule, and how many more were found. */
export function secretsColumn<T extends ReportObject>(): Column<T> {
  return {
    id: "secrets",
    title: "Secrets",
    className: styles.issue,
    sort: (o) => totalCount(severityCounts(o.report?.summary)),
    render: (o) => {
      const secrets = sortedSecrets(o.report?.secrets);
      if (secrets.length === 0) return <Muted>none</Muted>;
      return (
        <WithTooltip tooltip={secrets.map((s) => `${s.title}: ${s.target}`).join("\n")}>
          {secrets[0].title ?? secrets[0].ruleID}
          {secrets.length > 1 ? <Muted> +{secrets.length - 1} more</Muted> : null}
        </WithTooltip>
      );
    },
    search: (o) => (o.report?.secrets ?? []).map((s) => `${s.title} ${s.ruleID} ${s.target}`),
  };
}

export function numberColumn<T>(id: string, title: string, valueOf: (object: T) => number | undefined): Column<T> {
  return {
    id,
    title,
    className: `${styles.number} ${styles.countColumn}`,
    sort: (o) => valueOf(o) ?? 0,
    render: (o) => valueOf(o) ?? "N/A",
  };
}

export function formatColumn<T extends ReportObject>(): Column<T> {
  return {
    id: "format",
    title: "Format",
    className: styles.format,
    sort: (o) => o.report?.components?.bomFormat ?? "",
    render: (o) => (
      <Muted>
        {[o.report?.components?.bomFormat, o.report?.components?.specVersion].filter(Boolean).join(" ") || "N/A"}
      </Muted>
    ),
  };
}

const MATCHES_SHOWN = 3;

/** The packages that matched the search, such as `openssl 3.0.11`; only shown while searching. */
export function matchesColumn<T extends ReportObject>(): Column<T> {
  return {
    id: "matches",
    title: "Matches",
    className: styles.issue,
    when: (context) => context.query.trim().length > 0,
    sort: (o, context) => versionKey(matchPackages(o.report?.components?.components, context.query)[0]?.version),
    render: (o, context) => {
      const matches = matchPackages(o.report?.components?.components, context.query);
      if (matches.length === 0) return <Muted>–</Muted>;
      const all = matches.map((m) => `${m.name} ${m.version}\n${m.purl}`).join("\n\n");
      return (
        <WithTooltip tooltip={all}>
          {matches
            .slice(0, MATCHES_SHOWN)
            .map((m) => `${m.name} ${m.version}`)
            .join(", ")}
          {matches.length > MATCHES_SHOWN ? <Muted> +{matches.length - MATCHES_SHOWN} more</Muted> : null}
        </WithTooltip>
      );
    },
  };
}
