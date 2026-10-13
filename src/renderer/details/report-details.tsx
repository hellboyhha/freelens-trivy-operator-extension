// The drawer sections for each report kind. They add to the host's drawer, which already
// shows the metadata, so they show what the operator found, starting with what to do about it.

import { Renderer } from "@freelensapp/extensions";
import * as MobxReact from "mobx-react";
import React from "react";
import {
  avdUrl,
  countFixable,
  failedChecks,
  groupByPackage,
  hasFix,
  imageOf,
  type PackageGroup,
  passedChecks,
  resourceLabel,
  resourceOf,
  severityCounts,
  sortedSecrets,
  sortedVulnerabilities,
  ticketText,
} from "../api/trivy/report-model";
import { withErrorPage } from "../components/error-page";
import { applyFilters, chipOptions, type FilterSpec, toggleFilter, visibleSelection } from "../components/filters";
import { formatAge, limited } from "../components/format";
import { RescanAction } from "../components/rescan-action";
import { SeverityCount, SeverityLabel, SeverityStyles } from "../components/severity-count";
import { Banner, Button, Chips, Fixable, Muted, Segmented, SeverityBar, UiStyles } from "../components/ui";
import styles from "./report-details.module.scss";
import stylesInline from "./report-details.module.scss?inline";

import type {
  ChecksReportData,
  ComplianceSpec,
  ComplianceStatus,
  ExposedSecretReportData,
  SbomReportData,
  Vulnerability,
  VulnerabilityReportData,
} from "../api/trivy/common";

const { observer } = MobxReact;

const {
  Component: { DrawerItem, DrawerTitle, Table, TableCell, TableHead, TableRow, WithTooltip },
  Navigation: { hideDetails },
} = Renderer;

const VULNERABILITY_ROWS = 100;
const PACKAGE_ROWS = 100;
const SBOM_ROWS = 200;

type DetailsProps = Renderer.Component.KubeObjectDetailsProps<any> & { extension: Renderer.LensExtension };

const when = (timestamp?: string) => (timestamp ? `${formatAge(timestamp)} ago (${timestamp})` : "N/A");

function Link({ href, children }: { href?: string; children: React.ReactNode }) {
  return href?.startsWith("https://") ? (
    <a href={href} target="_blank" rel="noreferrer">
      {children}
    </a>
  ) : (
    <>{children}</>
  );
}

function More({ hidden, noun = "", onShowAll }: { hidden: number; noun?: string; onShowAll: () => void }) {
  if (hidden === 0) return null;
  return (
    <p className={styles.more}>
      {hidden} more {noun}not shown.
      <button type="button" className={styles.moreButton} onClick={onShowAll}>
        Show all
      </button>
    </p>
  );
}

/** The first thing a drawer shows: the counts, a bar, and how many findings an upgrade clears. */
function SummaryCard({ summary, fixable }: { summary?: Parameters<typeof severityCounts>[0]; fixable?: number }) {
  const counts = severityCounts(summary);
  return (
    <div className={styles.summary}>
      <div className={styles.big}>
        {(["critical", "high", "medium", "low"] as const).map((key) => (
          <div key={key}>
            <b>
              <SeverityCount severity={key} count={counts[key]} />
            </b>
            <span>{key}</span>
          </div>
        ))}
        {counts.unknown > 0 ? (
          <div>
            <b>
              <SeverityCount severity="unknown" count={counts.unknown} />
            </b>
            <span>unknown</span>
          </div>
        ) : null}
        {fixable !== undefined ? (
          <div className={styles.bigRight}>
            <b>
              <Fixable>{fixable}</Fixable>
            </b>
            <span>fixed by upgrading</span>
          </div>
        ) : null}
      </div>
      <SeverityBar counts={counts} />
    </div>
  );
}

/** Resource, image and scan details, in the host's own rows. */
function Meta({ object, report }: { object: any; report?: any }) {
  const ref = resourceOf(object.metadata);
  const os = report?.os?.family ? [report.os.family, report.os.name].filter(Boolean).join(" ") : "";
  return (
    <>
      <DrawerItem name="Resource">{resourceLabel(ref) || object.metadata?.name}</DrawerItem>
      {ref.namespace ? <DrawerItem name="Namespace">{ref.namespace}</DrawerItem> : null}
      {ref.container ? <DrawerItem name="Container">{ref.container}</DrawerItem> : null}
      {report?.artifact ? <DrawerItem name="Image">{imageOf(report.artifact)}</DrawerItem> : null}
      {report?.registry?.server ? <DrawerItem name="Registry">{report.registry.server}</DrawerItem> : null}
      {report?.artifact?.digest ? (
        <DrawerItem name="Digest">
          <span className={styles.digest}>{report.artifact.digest}</span>
        </DrawerItem>
      ) : null}
      {os ? <DrawerItem name="OS">{report?.os?.eosl ? `${os} (end of support life)` : os}</DrawerItem> : null}
      <DrawerItem name="Scanner">
        {[report?.scanner?.name, report?.scanner?.version].filter(Boolean).join(" ") || "N/A"}
      </DrawerItem>
      <DrawerItem name="Scanned">{when(report?.updateTimestamp)}</DrawerItem>
    </>
  );
}

// ---- vulnerabilities ------------------------------------------------------------------

const VULNERABILITY_FILTERS: FilterSpec<Vulnerability>[] = [
  { id: "critical", label: "Critical", group: "severity", predicate: (v) => v.severity === "CRITICAL" },
  { id: "high", label: "High", group: "severity", predicate: (v) => v.severity === "HIGH" },
  { id: "fix", label: "With a fix", predicate: hasFix },
];

function PackageCard({ group }: { group: PackageGroup }) {
  const key = (group.severity ?? "unknown").toLowerCase() as "critical" | "high" | "medium" | "low" | "unknown";
  return (
    <div className={styles.package}>
      <div className={styles.packageHead}>
        <SeverityCount severity={key} count={group.ids.length} />
        <b>{group.name}</b>
        <span className={styles.versions}>{group.fixed ? `${group.installed} → ${group.fixed}` : group.installed}</span>
        {group.fixed ? (
          <span className={styles.clears}>
            clears {group.clears} CVE{group.clears === 1 ? "" : "s"}
          </span>
        ) : (
          <span className={styles.nofix}>no fix yet</span>
        )}
      </div>
      <div className={styles.cves}>
        {group.findings.slice(0, 3).map((f) =>
          f.link?.startsWith("https://") ? (
            <a key={f.id} href={f.link} target="_blank" rel="noreferrer">
              {f.id}
            </a>
          ) : (
            <span key={f.id}>{f.id}</span>
          ),
        )}
        {group.findings.length > 3 ? <span>+{group.findings.length - 3}</span> : null}
      </div>
    </div>
  );
}

export const VulnerabilityDetails = observer((props: DetailsProps) =>
  withErrorPage(props, () => {
    const [view, setView] = React.useState<"package" | "cves">("package");
    const [selected, setSelected] = React.useState<ReadonlySet<string>>(new Set());
    const [showAll, setShowAll] = React.useState(false);
    const [showAllPackages, setShowAllPackages] = React.useState(false);
    const [copied, setCopied] = React.useState(false);
    const { object } = props;
    const report: VulnerabilityReportData | undefined = object?.report;
    if (!object || !String(object.kind).endsWith("VulnerabilityReport")) return <></>;

    const all = report?.vulnerabilities ?? [];
    const list = sortedVulnerabilities(applyFilters(all, VULNERABILITY_FILTERS, selected));
    const groups = groupByPackage(list);
    const { shown, hidden } = showAll ? { shown: list, hidden: 0 } : limited(list, VULNERABILITY_ROWS);
    const ticket = () =>
      ticketText(groups, {
        workload: resourceLabel(resourceOf(object.metadata)) || object.metadata?.name,
        image: imageOf(report?.artifact),
      });

    return (
      <>
        <style>{stylesInline}</style>
        <UiStyles />
        <SeverityStyles />
        <RescanAction items={[object]} after={hideDetails} />
        <DrawerTitle>Summary</DrawerTitle>
        <SummaryCard summary={report?.summary} fixable={countFixable(all)} />
        <Meta object={object} report={report} />
        <DrawerTitle>What to upgrade</DrawerTitle>
        {all.length === 0 ? (
          <DrawerItem name="Vulnerabilities">None found</DrawerItem>
        ) : (
          <>
            <div className={styles.tools}>
              <Segmented
                label="View"
                options={[
                  { id: "package", label: "By package" },
                  { id: "cves", label: "All CVEs" },
                ]}
                value={view}
                onChange={setView}
              />
              <span className={styles.toolsRight}>
                <Button
                  onClick={() => {
                    void navigator.clipboard?.writeText(ticket());
                    setCopied(true);
                    setTimeout(() => setCopied(false), 2000);
                  }}
                >
                  {copied ? "Copied ✓" : "Copy for ticket"}
                </Button>
              </span>
            </div>
            <Chips
              options={chipOptions(VULNERABILITY_FILTERS)}
              selected={visibleSelection(VULNERABILITY_FILTERS, selected)}
              onToggle={(id) => setSelected(toggleFilter(VULNERABILITY_FILTERS, selected, id))}
            />
            {list.length === 0 ? (
              <Muted>Nothing matches these filters.</Muted>
            ) : view === "package" ? (
              <>
                {(showAllPackages ? groups : groups.slice(0, PACKAGE_ROWS)).map((group) => (
                  <PackageCard key={`${group.name}@${group.installed}`} group={group} />
                ))}
                {showAllPackages ? null : (
                  <More
                    hidden={Math.max(0, groups.length - PACKAGE_ROWS)}
                    noun="packages "
                    onShowAll={() => setShowAllPackages(true)}
                  />
                )}
              </>
            ) : (
              <>
                <Table scrollable={false} sortSyncWithUrl={false} className={styles.table}>
                  <TableHead flat sticky={false}>
                    <TableCell className={styles.severity}>Severity</TableCell>
                    <TableCell className={styles.id}>ID</TableCell>
                    <TableCell className={styles.package}>Package</TableCell>
                    <TableCell className={styles.version}>Installed</TableCell>
                    <TableCell className={styles.version}>Fixed</TableCell>
                  </TableHead>
                  {shown.map((v, index) => (
                    <TableRow key={`${v.vulnerabilityID}-${v.resource}-${v.installedVersion}-${index}`} nowrap>
                      <TableCell className={styles.severity}>
                        <SeverityLabel severity={v.severity} />
                      </TableCell>
                      <TableCell className={styles.id}>
                        <WithTooltip tooltip={v.title}>
                          <Link href={v.primaryLink}>{v.vulnerabilityID}</Link>
                        </WithTooltip>
                      </TableCell>
                      <TableCell className={styles.package}>
                        <WithTooltip>{v.resource}</WithTooltip>
                      </TableCell>
                      <TableCell className={styles.version}>
                        <WithTooltip>{v.installedVersion}</WithTooltip>
                      </TableCell>
                      <TableCell className={styles.version}>
                        <WithTooltip>{v.fixedVersion || "no fix"}</WithTooltip>
                      </TableCell>
                    </TableRow>
                  ))}
                </Table>
                <More hidden={hidden} onShowAll={() => setShowAll(true)} />
              </>
            )}
          </>
        )}
      </>
    );
  }),
);

// ---- exposed secrets ------------------------------------------------------------------

export const SecretDetails = observer((props: DetailsProps) =>
  withErrorPage(props, () => {
    const { object } = props;
    const report: ExposedSecretReportData | undefined = object?.report;
    if (!object || object.kind !== "ExposedSecretReport") return <></>;
    const secrets = sortedSecrets(report?.secrets);
    return (
      <>
        <style>{stylesInline}</style>
        <UiStyles />
        <SeverityStyles />
        <RescanAction items={[object]} after={hideDetails} />
        <DrawerTitle>Summary</DrawerTitle>
        <SummaryCard summary={report?.summary} />
        <Meta object={object} report={report} />
        <DrawerTitle>Exposed secrets</DrawerTitle>
        {secrets.length === 0 ? (
          <DrawerItem name="Secrets">None found</DrawerItem>
        ) : (
          <>
            <div style={{ margin: "8px 0" }}>
              <Banner>
                Rotate each secret, then rebuild the image. Deleting the file in a later layer does not remove it from
                the image. The matched text is never shown.
              </Banner>
            </div>
            <Table scrollable={false} sortSyncWithUrl={false} className={styles.table}>
              <TableHead flat sticky={false}>
                <TableCell className={styles.severity}>Severity</TableCell>
                <TableCell className={styles.id}>Rule</TableCell>
                <TableCell className={styles.title}>File</TableCell>
              </TableHead>
              {secrets.map((s, index) => (
                <TableRow key={`${s.ruleID}-${s.target}-${index}`} nowrap>
                  <TableCell className={styles.severity}>
                    <SeverityLabel severity={s.severity} />
                  </TableCell>
                  <TableCell className={styles.id}>
                    <WithTooltip tooltip={s.title}>{s.title ?? s.ruleID}</WithTooltip>
                  </TableCell>
                  <TableCell className={styles.title}>
                    <WithTooltip>{s.target}</WithTooltip>
                  </TableCell>
                </TableRow>
              ))}
            </Table>
          </>
        )}
      </>
    );
  }),
);

// ---- configuration, RBAC and infrastructure checks ------------------------------------

const CHECK_KINDS = [
  "ConfigAuditReport",
  "ClusterConfigAuditReport",
  "RbacAssessmentReport",
  "ClusterRbacAssessmentReport",
  "InfraAssessmentReport",
  "ClusterInfraAssessmentReport",
];

export const ChecksDetails = observer((props: DetailsProps) =>
  withErrorPage(props, () => {
    const { object } = props;
    const report: ChecksReportData | undefined = object?.report;
    if (!object || !CHECK_KINDS.includes(object.kind)) return <></>;
    const failed = failedChecks(report?.checks);
    return (
      <>
        <style>{stylesInline}</style>
        <UiStyles />
        <SeverityStyles />
        <RescanAction items={[object]} after={hideDetails} />
        <DrawerTitle>Summary</DrawerTitle>
        <SummaryCard summary={report?.summary} />
        <Meta object={object} report={report} />
        <DrawerTitle>Failed checks</DrawerTitle>
        {failed.length === 0 ? (
          <DrawerItem name="Checks">No failed checks</DrawerItem>
        ) : (
          failed.map((check, index) => (
            <details key={`${check.checkID}-${index}`} className={styles.check} open={index < 3}>
              <summary>
                <SeverityLabel severity={check.severity} />
                <span className={styles.checkTitle}>{check.title}</span>
                <Link href={avdUrl(check.checkID) ?? undefined}>{check.checkID}</Link>
              </summary>
              <div className={styles.checkBody}>
                {check.messages?.map((message) => (
                  <div key={message}>{message}</div>
                ))}
                {check.remediation ? <div className={styles.fixLine}>Fix: {check.remediation}</div> : null}
              </div>
            </details>
          ))
        )}
        <DrawerItem name="Passed">{passedChecks(report?.checks)} checks passed</DrawerItem>
      </>
    );
  }),
);

// ---- SBOM -----------------------------------------------------------------------------

export const SbomDetails = observer((props: DetailsProps) =>
  withErrorPage(props, () => {
    const [filter, setFilter] = React.useState("");
    const [showAll, setShowAll] = React.useState(false);
    const { object } = props;
    const report: SbomReportData | undefined = object?.report;
    if (!object || !String(object.kind).endsWith("SbomReport")) return <></>;

    const all = report?.components?.components ?? [];
    const needle = filter.trim().toLowerCase();
    const list = needle ? all.filter((c) => `${c.name} ${c.version} ${c.purl}`.toLowerCase().includes(needle)) : all;
    const { shown, hidden } = showAll ? { shown: list, hidden: 0 } : limited(list, SBOM_ROWS);

    return (
      <>
        <style>{stylesInline}</style>
        <UiStyles />
        <SeverityStyles />
        <DrawerTitle>Report</DrawerTitle>
        <Meta object={object} report={report} />
        <DrawerItem name="Format">
          {[report?.components?.bomFormat, report?.components?.specVersion].filter(Boolean).join(" ") || "N/A"}
        </DrawerItem>
        <DrawerItem name="Components">{report?.summary?.componentsCount ?? all.length}</DrawerItem>
        <DrawerItem name="Dependencies">{report?.summary?.dependenciesCount ?? "N/A"}</DrawerItem>
        <DrawerTitle>Components</DrawerTitle>
        <div className={styles.tools}>
          <input
            className={styles.search}
            type="search"
            placeholder="Filter by name, version or purl"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>
        <Table scrollable={false} sortSyncWithUrl={false} className={styles.table}>
          <TableHead flat sticky={false}>
            <TableCell className={styles.name}>Name</TableCell>
            <TableCell className={styles.version}>Version</TableCell>
            <TableCell className={styles.version}>Type</TableCell>
          </TableHead>
          {shown.map((c, index) => (
            <TableRow key={`${c["bom-ref"] ?? c.purl ?? c.name}-${index}`} nowrap>
              <TableCell className={styles.name}>
                <WithTooltip tooltip={c.purl}>{c.name}</WithTooltip>
              </TableCell>
              <TableCell className={styles.version}>
                <WithTooltip>{c.version}</WithTooltip>
              </TableCell>
              <TableCell className={styles.version}>{c.type}</TableCell>
            </TableRow>
          ))}
        </Table>
        <More hidden={hidden} onShowAll={() => setShowAll(true)} />
      </>
    );
  }),
);

// ---- compliance -----------------------------------------------------------------------

export const ComplianceDetails = observer((props: DetailsProps) =>
  withErrorPage(props, () => {
    const { object } = props;
    if (!object || object.kind !== "ClusterComplianceReport") return <></>;
    const spec: ComplianceSpec = object.spec ?? {};
    const status: ComplianceStatus = object.status ?? {};
    const meta = spec.compliance;
    const controls = new Map((meta?.controls ?? []).map((c) => [c.id, c]));
    const rows = [...(status.summaryReport?.controlCheck ?? [])].sort(
      (a, b) =>
        (b.totalFail ?? 0) - (a.totalFail ?? 0) || (a.id ?? "").localeCompare(b.id ?? "", undefined, { numeric: true }),
    );
    return (
      <>
        <style>{stylesInline}</style>
        <UiStyles />
        <SeverityStyles />
        <DrawerTitle>Benchmark</DrawerTitle>
        <DrawerItem name="Title">{meta?.title ?? object.metadata?.name}</DrawerItem>
        {meta?.description ? <DrawerItem name="Description">{meta.description}</DrawerItem> : null}
        <DrawerItem name="Type">{[meta?.type, meta?.version].filter(Boolean).join(" ") || "N/A"}</DrawerItem>
        {meta?.platform ? <DrawerItem name="Platform">{meta.platform}</DrawerItem> : null}
        <DrawerItem name="Schedule">{spec.cron ?? "N/A"}</DrawerItem>
        <DrawerItem name="Updated">{when(status.updateTimestamp)}</DrawerItem>
        <DrawerItem name="Controls">
          <span className={styles.counts}>
            <span>
              <SeverityCount severity="critical" count={status.summary?.failCount ?? 0} /> failing
            </span>
            <span>{status.summary?.passCount ?? 0} passing</span>
          </span>
        </DrawerItem>
        {meta?.relatedResources?.length ? (
          <DrawerItem name="Reference">
            {meta.relatedResources.map((url) => (
              <div key={url}>
                <Link href={url}>{url}</Link>
              </div>
            ))}
          </DrawerItem>
        ) : null}
        <DrawerTitle>Controls</DrawerTitle>
        {rows.length === 0 ? (
          <DrawerItem name="Controls">
            {spec.reportType === "summary" ? "No control results yet" : "No controls"}
          </DrawerItem>
        ) : (
          <Table scrollable={false} sortSyncWithUrl={false} className={styles.table}>
            <TableHead flat sticky={false}>
              <TableCell className={styles.id}>Control</TableCell>
              <TableCell className={styles.severity}>Severity</TableCell>
              <TableCell className={styles.title}>Name</TableCell>
              <TableCell className={styles.count}>Failing</TableCell>
            </TableHead>
            {rows.map((row) => (
              <TableRow key={row.id} nowrap>
                <TableCell className={styles.id}>{row.id}</TableCell>
                <TableCell className={styles.severity}>
                  <SeverityLabel severity={row.severity} />
                </TableCell>
                <TableCell className={styles.title}>
                  <WithTooltip tooltip={controls.get(row.id)?.description}>{row.name}</WithTooltip>
                </TableCell>
                <TableCell className={styles.count}>
                  <SeverityCount severity="critical" count={row.totalFail ?? 0} />
                </TableCell>
              </TableRow>
            ))}
          </Table>
        )}
      </>
    );
  }),
);
