// The Overview: what to worry about first. A headline, one tile per kind of finding, the
// images where an upgrade pays off most, and where each compliance benchmark stands.
// It reads the stores only and follows the host's namespace filter.

import { Renderer } from "@freelensapp/extensions";
import * as MobxReact from "mobx-react";
import { maybe } from "../../common/utils";
import {
  ClusterComplianceReport,
  ClusterConfigAuditReport,
  ClusterInfraAssessmentReport,
  ClusterRbacAssessmentReport,
  ClusterVulnerabilityReport,
  ConfigAuditReport,
  ExposedSecretReport,
  InfraAssessmentReport,
  RbacAssessmentReport,
  VulnerabilityReport,
} from "../api/trivy";
import { resourceOf, severityCounts, totalCount } from "../api/trivy/report-model";
import { withErrorPage } from "../components/error-page";
import { formatAge } from "../components/format";
import {
  benchmarkRows,
  distinctImages,
  fixFirst,
  headline,
  type KindSummary,
  sourceState,
  summarizeKind,
  tileAvailability,
} from "../components/overview-model";
import { SeverityStyles } from "../components/severity-count";
import {
  Button,
  Dot,
  EmptyState,
  Fixable,
  ImageName,
  Legend,
  Muted,
  PassFailBar,
  SeverityBar,
  SeverityNumber,
  Skeleton,
  TwoLine,
  UiStyles,
} from "../components/ui";
import { type LoadableStore, useLoadedStores } from "../components/use-loaded-stores";
import {
  COMPLIANCE_PAGE_ID,
  extensionPageUrl,
  MISCONFIGURATIONS_PAGE_ID,
  SECRETS_PAGE_ID,
  VULNERABILITIES_PAGE_ID,
} from "../navigation";
import styles from "./overview-page.module.scss";
import stylesInline from "./overview-page.module.scss?inline";

const { observer } = MobxReact;

const {
  Component: { MaybeLink, NamespaceSelectFilter, Table, TableCell, TableHead, TableRow, TabLayout },
  Navigation: { getDetailsUrl },
} = Renderer;

export interface OverviewPageProps {
  extension: Renderer.LensExtension;
}

interface StoreLike extends LoadableStore {
  contextItems: any[];
}

const store = (kind: { getStore(): unknown }): StoreLike | null => maybe(() => kind.getStore()) as StoreLike | null;
const items = (s: StoreLike | null): any[] => s?.contextItems ?? [];
const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;
const partial = (missing: number, total: number) =>
  missing > 0 ? `${missing} of ${total} sources not available` : undefined;

function Tile(props: {
  label: string;
  value: React.ReactNode;
  unit?: string;
  to: string;
  bar: React.ReactNode;
  legend?: React.ReactNode;
  note?: string;
  /** Set when none of the tile's reports can be read: it says so instead of showing 0. */
  unavailable?: "failed" | "unavailable";
}) {
  if (props.unavailable) {
    return (
      <div className={styles.tile}>
        <span className={styles.tileLabel}>{props.label}</span>
        <span className={styles.tileValue}>
          <span className={styles.tileNA}>Not available</span>
        </span>
        <span className={styles.tileNote}>
          {props.unavailable === "failed"
            ? "The reports could not be loaded."
            : "This cluster has no reports of this kind."}
        </span>
      </div>
    );
  }
  return (
    <MaybeLink to={props.to} className={styles.tile}>
      <span className={styles.tileLabel}>{props.label}</span>
      <span className={styles.tileValue}>
        {props.value}
        {props.unit ? <span className={styles.tileUnit}>{props.unit}</span> : null}
      </span>
      {props.bar}
      {props.legend}
      {props.note ? <span className={styles.tileNote}>{props.note}</span> : null}
    </MaybeLink>
  );
}

function SeverityLegend({ summary }: { summary: KindSummary }) {
  return (
    <Legend>
      {(["critical", "high", "medium"] as const).map((key) => (
        <span key={key}>
          <Dot tone={key} />
          <b>{summary.counts[key]}</b> {key === "medium" ? "med" : key}
        </span>
      ))}
    </Legend>
  );
}

export const OverviewPage = observer((props: OverviewPageProps) =>
  withErrorPage(props, () => {
    const { extension } = props;
    const stores = {
      vulns: store(VulnerabilityReport),
      clusterVulns: store(ClusterVulnerabilityReport),
      secrets: store(ExposedSecretReport),
      configs: store(ConfigAuditReport),
      clusterConfigs: store(ClusterConfigAuditReport),
      rbac: store(RbacAssessmentReport),
      clusterRbac: store(ClusterRbacAssessmentReport),
      infra: store(InfraAssessmentReport),
      clusterInfra: store(ClusterInfraAssessmentReport),
      compliance: store(ClusterComplianceReport),
    };
    // SBOM reports are not loaded here: each one carries every component of an image.
    useLoadedStores(Object.entries(stores).map(([label, s]) => ({ label, store: s })));

    const states = Object.fromEntries(Object.entries(stores).map(([key, s]) => [key, sourceState(s)])) as Record<
      keyof typeof stores,
      ReturnType<typeof sourceState>
    >;
    const loading = states.vulns === "loading";
    const vulnerabilities = summarizeKind(items(stores.vulns), items(stores.clusterVulns));
    const secrets = summarizeKind(items(stores.secrets));
    const misconfigurationKinds = [
      "configs",
      "clusterConfigs",
      "rbac",
      "clusterRbac",
      "infra",
      "clusterInfra",
    ] as const;
    const misconfigurations = summarizeKind(...misconfigurationKinds.map((key) => items(stores[key])));
    const vulnerabilityTile = tileAvailability([states.vulns, states.clusterVulns]);
    const secretsTile = tileAvailability([states.secrets]);
    const misconfigurationTile = tileAvailability(misconfigurationKinds.map((key) => states[key]));
    const complianceTile = tileAvailability([states.compliance]);
    const benchmarks = benchmarkRows(items(stores.compliance));
    const failing = benchmarks.reduce((sum, b) => sum + b.failing, 0);
    const passing = benchmarks.reduce((sum, b) => sum + b.passing, 0);
    const lead = headline(items(stores.vulns), items(stores.clusterVulns));
    const rows = fixFirst(items(stores.vulns), 8);
    const secretImages = distinctImages(
      items(stores.secrets).filter((r) => totalCount(severityCounts(r.report?.summary)) > 0),
    );
    const loadFailed = states.vulns === "failed" && vulnerabilities.reports === 0;
    const nothingYet =
      !loading && !loadFailed && vulnerabilities.reports + secrets.reports + misconfigurations.reports === 0;
    const retry = () => {
      for (const s of Object.values(stores)) void s?.loadAll({ merge: true });
    };
    const url = (pageId: string) => extensionPageUrl(extension.name, pageId);

    return (
      <TabLayout scrollable>
        <UiStyles />
        <style>{stylesInline}</style>
        <SeverityStyles />
        <div className={styles.overview}>
          <div className={styles.header}>
            <h5 className={styles.title}>Overview</h5>
            <div className={styles.namespaces}>
              <NamespaceSelectFilter id="trivy-overview-namespace-filter" />
            </div>
          </div>

          {loading ? (
            <div className={styles.skeletons}>
              <Skeleton count={4} />
            </div>
          ) : loadFailed ? (
            <EmptyState
              title="Could not load Trivy Operator reports"
              actions={
                <Button primary onClick={retry}>
                  Try again
                </Button>
              }
            >
              <p>
                The cluster refused or failed the request for the vulnerability reports. Check that your account may
                list the <code>aquasecurity.github.io</code> resources, then try again.
              </p>
            </EmptyState>
          ) : nothingYet ? (
            <EmptyState
              title="No Trivy Operator reports in the selected namespaces"
              actions={
                <Button primary onClick={() => Renderer.K8sApi.namespaceStore.clearSelected()}>
                  Show all namespaces
                </Button>
              }
            >
              <p>
                This page follows the namespace filter at the top. A fresh Freelens selects only <code>default</code>,
                and the operator may still be on its first scans.
              </p>
            </EmptyState>
          ) : (
            <>
              <p className={styles.lead}>
                {lead.critical > 0 ? (
                  <>
                    <b className={styles.critical}>{lead.critical} critical</b>{" "}
                    {lead.critical === 1 ? "vulnerability" : "vulnerabilities"} across{" "}
                    {plural(lead.criticalImages, "image")},{" "}
                    <b>
                      {lead.criticalFixable} {lead.criticalFixable === 1 ? "has" : "have"} a fix
                    </b>
                    .
                  </>
                ) : (
                  <>No critical vulnerabilities.</>
                )}
                {lead.lastScan ? (
                  <>
                    {" "}
                    Last scan <b>{formatAge(lead.lastScan)} ago</b>.
                  </>
                ) : null}
              </p>

              <div className={styles.strip}>
                <Tile
                  label="Vulnerabilities"
                  value={vulnerabilities.total.toLocaleString()}
                  to={url(VULNERABILITIES_PAGE_ID)}
                  unavailable={vulnerabilityTile.reason}
                  bar={<SeverityBar counts={vulnerabilities.counts} />}
                  legend={<SeverityLegend summary={vulnerabilities} />}
                  note={partial(vulnerabilityTile.missing, 2) ?? `in ${plural(vulnerabilities.reports, "report")}`}
                />
                <Tile
                  label="Exposed secrets"
                  value={secrets.total}
                  to={url(SECRETS_PAGE_ID)}
                  unavailable={secretsTile.reason}
                  bar={<SeverityBar counts={secrets.counts} />}
                  legend={<SeverityLegend summary={secrets} />}
                  note={`in ${plural(secretImages, "image")}`}
                />
                <Tile
                  label="Misconfigurations"
                  value={misconfigurations.total}
                  to={url(MISCONFIGURATIONS_PAGE_ID)}
                  unavailable={misconfigurationTile.reason}
                  bar={<SeverityBar counts={misconfigurations.counts} />}
                  legend={<SeverityLegend summary={misconfigurations} />}
                  note={
                    partial(misconfigurationTile.missing, misconfigurationKinds.length) ??
                    "config audit · RBAC · infrastructure"
                  }
                />
                <Tile
                  label="Compliance"
                  value={failing}
                  unit="controls failing"
                  to={url(COMPLIANCE_PAGE_ID)}
                  unavailable={complianceTile.reason}
                  bar={<PassFailBar passing={passing} failing={failing} />}
                  legend={
                    <Legend>
                      <span>
                        <Dot tone="ok" />
                        <b>{passing}</b> passing
                      </span>
                    </Legend>
                  }
                  note={plural(benchmarks.length, "benchmark")}
                />
              </div>

              <div className={styles.stack}>
                {rows.length > 0 ? (
                  <div className={styles.section}>
                    <h6 className={styles.sectionTitle}>Fix first</h6>
                    <Table scrollable={false} sortSyncWithUrl={false} className={styles.table}>
                      <TableHead flat sticky={false}>
                        <TableCell className={styles.workload}>Workload</TableCell>
                        <TableCell className={styles.image}>Image</TableCell>
                        <TableCell className={styles.severityNumber}>Critical</TableCell>
                        <TableCell className={styles.severityNumber}>High</TableCell>
                        <TableCell className={styles.severityNumber}>Medium</TableCell>
                        <TableCell className={styles.severityNumber}>Low</TableCell>
                        <TableCell className={styles.clears}>Upgrade clears</TableCell>
                      </TableHead>
                      {rows.map(({ item, counts, fixable, total }) => {
                        const ref = resourceOf(item.metadata);
                        return (
                          <TableRow key={item.getId()} nowrap>
                            <TableCell className={styles.workload}>
                              <MaybeLink to={getDetailsUrl(item.selfLink)}>
                                <TwoLine
                                  title={ref.name || item.getName()}
                                  subtitle={[ref.namespace, ref.kind].filter(Boolean).join(" · ")}
                                />
                              </MaybeLink>
                            </TableCell>
                            <TableCell className={styles.image}>
                              <ImageName
                                repository={item.report?.artifact?.repository}
                                tag={item.report?.artifact?.tag}
                                title={item.report?.artifact?.digest}
                              />
                            </TableCell>
                            {(["critical", "high", "medium", "low"] as const).map((severity) => (
                              <TableCell key={severity} className={styles.severityNumber}>
                                <SeverityNumber counts={counts} severity={severity} />
                              </TableCell>
                            ))}
                            <TableCell className={styles.clears}>
                              {fixable > 0 ? <Fixable>{`${fixable} of ${total}`}</Fixable> : <Muted>no fix yet</Muted>}
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </Table>
                  </div>
                ) : null}

                {benchmarks.length > 0 ? (
                  <div className={styles.section}>
                    <h6 className={styles.sectionTitle}>Compliance</h6>
                    <Table scrollable={false} sortSyncWithUrl={false} className={styles.compliance}>
                      <TableHead flat sticky={false}>
                        <TableCell className={styles.benchmarkName}>Benchmark</TableCell>
                        <TableCell className={styles.passFail}>Failing</TableCell>
                        <TableCell className={styles.passFail}>Passing</TableCell>
                      </TableHead>
                      {benchmarks.map((row) => (
                        <TableRow key={row.id} nowrap>
                          <TableCell className={styles.benchmarkName}>
                            <MaybeLink to={url(COMPLIANCE_PAGE_ID)}>{row.title}</MaybeLink>
                          </TableCell>
                          <TableCell className={`${styles.passFail} ${styles.failingCount}`}>{row.failing}</TableCell>
                          <TableCell className={styles.passFail}>{row.passing}</TableCell>
                        </TableRow>
                      ))}
                    </Table>
                  </div>
                ) : null}
              </div>
            </>
          )}
        </div>
      </TabLayout>
    );
  }),
);
