// The list pages. Each kind is a thin definition over the list factory: its columns, its
// filter chips and the column it opens sorted by. The pages a user opens put a scope switch
// (namespaced or cluster-scoped) and, for misconfigurations, tabs above those lists.

import { Renderer } from "@freelensapp/extensions";
import * as MobxReact from "mobx-react";
import React from "react";
import { maybe } from "../../common/utils";
import {
  ClusterConfigAuditReport,
  ClusterInfraAssessmentReport,
  ClusterRbacAssessmentReport,
  ClusterSbomReport,
  ClusterVulnerabilityReport,
  ConfigAuditReport,
  ExposedSecretReport,
  InfraAssessmentReport,
  RbacAssessmentReport,
  SbomReport,
  VulnerabilityReport,
} from "../api/trivy";
import { countFixable, severityCounts, totalCount } from "../api/trivy/report-model";
import { withErrorPage } from "../components/error-page";
import { Centered, PageFrame } from "../components/page-frame";
import {
  fixableColumn,
  formatColumn,
  imageColumn,
  matchesColumn,
  numberColumn,
  type ReportObject,
  scannedColumn,
  secretsColumn,
  severityColumn,
  workloadColumn,
  worstIssueColumn,
} from "../components/report-columns";
import { createReportListPage } from "../components/report-list";
import { Button, EmptyState, Segmented, Tabs } from "../components/ui";

import type { FilterSpec } from "../components/filters";

const { observer } = MobxReact;

const summaryOf = (o: ReportObject) => o.report?.summary;
const counts = (o: ReportObject) => severityCounts(summaryOf(o));

const severityChips: FilterSpec<ReportObject>[] = [
  { id: "critical", label: "Critical", group: "severity", predicate: (o) => counts(o).critical > 0 },
  { id: "high", label: "High", group: "severity", predicate: (o) => counts(o).high > 0 },
];
const hideClean: FilterSpec<ReportObject> = {
  id: "hideClean",
  label: "Hide Clean",
  predicate: (o) => totalCount(counts(o)) > 0,
};

const vulnerabilityColumns = [
  workloadColumn<ReportObject>(),
  imageColumn<ReportObject>(),
  severityColumn(summaryOf),
  fixableColumn<ReportObject>(),
  scannedColumn<ReportObject>(),
];
const vulnerabilityFilters: FilterSpec<ReportObject>[] = [
  ...severityChips,
  { id: "fixable", label: "Fixable Only", predicate: (o) => countFixable(o.report?.vulnerabilities) > 0 },
  hideClean,
];
const checksColumns = [
  workloadColumn<ReportObject>(),
  worstIssueColumn<ReportObject>(),
  severityColumn(summaryOf),
  scannedColumn<ReportObject>(),
];
const checksFilters = [...severityChips, hideClean];

const sbomColumns = [
  workloadColumn<ReportObject>(),
  imageColumn<ReportObject>(),
  numberColumn<ReportObject>("components", "Components", (o) => (o.report as any)?.summary?.componentsCount),
  numberColumn<ReportObject>("dependencies", "Dependencies", (o) => (o.report as any)?.summary?.dependenciesCount),
  formatColumn<ReportObject>(),
  scannedColumn<ReportObject>(),
  matchesColumn<ReportObject>(),
];

// ---- one list per kind ----------------------------------------------------------------

const VulnerabilitiesList = createReportListPage<ReportObject>({
  tableId: "trivyVulnerabilitiesTable",
  title: VulnerabilityReport.crd.title,
  kind: VulnerabilityReport.kind,
  getStore: () => VulnerabilityReport.getStore(),
  columns: vulnerabilityColumns,
  filters: vulnerabilityFilters,
  defaultSort: "severity",
});

const ClusterVulnerabilitiesList = createReportListPage<ReportObject>({
  tableId: "trivyClusterVulnerabilitiesTable",
  title: ClusterVulnerabilityReport.crd.title,
  kind: ClusterVulnerabilityReport.kind,
  getStore: () => ClusterVulnerabilityReport.getStore(),
  columns: vulnerabilityColumns,
  filters: vulnerabilityFilters,
  defaultSort: "severity",
});

const ExposedSecretsList = createReportListPage<ReportObject>({
  tableId: "trivyExposedSecretsTable",
  title: ExposedSecretReport.crd.title,
  kind: ExposedSecretReport.kind,
  getStore: () => ExposedSecretReport.getStore(),
  columns: [
    workloadColumn<ReportObject>(),
    imageColumn<ReportObject>(),
    secretsColumn<ReportObject>(),
    severityColumn(summaryOf),
    scannedColumn<ReportObject>(),
  ],
  filters: [...severityChips, hideClean],
  defaultFilters: ["hideClean"],
  defaultSort: "severity",
});

const checksList = (kind: { getStore(): unknown; kind: string; crd: { title: string } }, tableId: string) =>
  createReportListPage<ReportObject>({
    tableId,
    title: kind.crd.title,
    kind: kind.kind,
    getStore: () => kind.getStore(),
    columns: checksColumns,
    filters: checksFilters,
    defaultFilters: ["hideClean"],
    defaultSort: "severity",
  });

const ConfigAuditList = checksList(ConfigAuditReport, "trivyConfigAuditsTable");
const ClusterConfigAuditList = checksList(ClusterConfigAuditReport, "trivyClusterConfigAuditsTable");
const RbacList = checksList(RbacAssessmentReport, "trivyRbacTable");
const ClusterRbacList = checksList(ClusterRbacAssessmentReport, "trivyClusterRbacTable");
const InfraList = checksList(InfraAssessmentReport, "trivyInfraTable");
const ClusterInfraList = checksList(ClusterInfraAssessmentReport, "trivyClusterInfraTable");

const SbomList = createReportListPage<ReportObject>({
  tableId: "trivySbomsTable",
  title: SbomReport.crd.title,
  kind: SbomReport.kind,
  getStore: () => SbomReport.getStore(),
  columns: sbomColumns,
  packageSearch: true,
  defaultSort: "components",
  rescan: false,
});

const ClusterSbomList = createReportListPage<ReportObject>({
  tableId: "trivyClusterSbomsTable",
  title: ClusterSbomReport.crd.title,
  kind: ClusterSbomReport.kind,
  getStore: () => ClusterSbomReport.getStore(),
  columns: sbomColumns,
  packageSearch: true,
  defaultSort: "components",
  rescan: false,
});

/** Every per-kind list by the name of its fixture; the pages below choose between them. */
export const LISTS = {
  vulnerabilityreport: VulnerabilitiesList,
  clustervulnerabilityreport: ClusterVulnerabilitiesList,
  exposedsecretreport: ExposedSecretsList,
  configauditreport: ConfigAuditList,
  clusterconfigauditreport: ClusterConfigAuditList,
  rbacassessmentreport: RbacList,
  clusterrbacassessmentreport: ClusterRbacList,
  infraassessmentreport: InfraList,
  clusterinfraassessmentreport: ClusterInfraList,
  sbomreport: SbomList,
  clustersbomreport: ClusterSbomList,
};

// ---- the pages a user opens -----------------------------------------------------------

export interface PageProps {
  extension: Renderer.LensExtension;
  /** Passed to a list so it can show the scope switch at the right of its chips. */
  aside?: React.ReactNode;
}

type Scope = "namespaced" | "cluster";
type ListPage = React.ComponentType<PageProps>;

const SCOPES = [
  { id: "namespaced" as const, label: "Namespaced" },
  { id: "cluster" as const, label: "Cluster-Scoped" },
];

const hasCount = (kind: { getStore(): unknown }): number | undefined =>
  (maybe(() => kind.getStore()) as { isLoaded?: boolean; contextItems?: unknown[] } | null)?.contextItems?.length;

/** The vulnerability, SBOM or secrets list with a switch between namespaced and cluster-scoped reports. */
function scopedPage(namespaced: ListPage, cluster?: ListPage) {
  return observer((props: PageProps) =>
    withErrorPage(props, () => {
      const [scope, setScope] = React.useState<Scope>("namespaced");
      const Page = scope === "cluster" && cluster ? cluster : namespaced;
      const aside = cluster ? (
        <Segmented label="Scope" options={SCOPES} value={scope} onChange={setScope} />
      ) : undefined;
      return (
        <PageFrame>
          <Page {...props} aside={aside} />
        </PageFrame>
      );
    }),
  );
}

export const VulnerabilitiesPage = scopedPage(VulnerabilitiesList, ClusterVulnerabilitiesList);
export const SecretsPage = scopedPage(ExposedSecretsList);

type CheckTab = "config" | "rbac" | "infra";

const CHECK_TABS: Record<
  CheckTab,
  { label: string; kind: { getStore(): unknown }; page: ListPage; cluster: ListPage }
> = {
  config: { label: "Config Audit", kind: ConfigAuditReport, page: ConfigAuditList, cluster: ClusterConfigAuditList },
  rbac: { label: "RBAC", kind: RbacAssessmentReport, page: RbacList, cluster: ClusterRbacList },
  infra: { label: "Infrastructure", kind: InfraAssessmentReport, page: InfraList, cluster: ClusterInfraList },
};

/** Config Audit, RBAC and infrastructure checks: three tabs and the scope switch. */
export const MisconfigurationsPage = observer((props: PageProps) =>
  withErrorPage(props, () => {
    const [tab, setTab] = React.useState<CheckTab>("config");
    const [scope, setScope] = React.useState<Scope>("namespaced");
    const current = CHECK_TABS[tab];
    const Page = scope === "cluster" ? current.cluster : current.page;
    return (
      <PageFrame
        head={
          <Tabs
            tabs={(Object.keys(CHECK_TABS) as CheckTab[]).map((id) => {
              const n = hasCount(CHECK_TABS[id].kind);
              return { id, label: n === undefined ? CHECK_TABS[id].label : `${CHECK_TABS[id].label}  ${n}` };
            })}
            value={tab}
            onChange={setTab}
          />
        }
      >
        <Page {...props} aside={<Segmented label="Scope" options={SCOPES} value={scope} onChange={setScope} />} />
      </PageFrame>
    );
  }),
);

let sbomsRequested = false;

/** SBOM reports list every component of an image, so nothing is loaded until the user asks. */
export const SbomsPage = observer((props: PageProps) =>
  withErrorPage(props, () => {
    const [requested, setRequested] = React.useState(sbomsRequested);
    const [scope, setScope] = React.useState<Scope>("namespaced");
    if (!requested) {
      return (
        <PageFrame>
          <Centered>
            <EmptyState
              title="SBOM reports load on request"
              actions={
                <Button
                  primary
                  onClick={() => {
                    sbomsRequested = true;
                    setRequested(true);
                  }}
                >
                  Load SBOMs
                </Button>
              }
            >
              <p>
                Each SBOM lists every component of an image, so on a large cluster the reports can total hundreds of
                megabytes. They are loaded only when you ask.
              </p>
              <p>Once loaded, you can search every report for a package by name, version or purl.</p>
            </EmptyState>
          </Centered>
        </PageFrame>
      );
    }
    const Page = scope === "cluster" ? ClusterSbomList : SbomList;
    return (
      <PageFrame>
        <Page {...props} aside={<Segmented label="Scope" options={SCOPES} value={scope} onChange={setScope} />} />
      </PageFrame>
    );
  }),
);
