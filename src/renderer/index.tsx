import { Renderer } from "@freelensapp/extensions";
import {
  ClusterComplianceReport,
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
} from "./api/trivy";
import { createAvailableVersionPage } from "./components/available-version";
import {
  ChecksDetails,
  ComplianceDetails,
  SbomDetails,
  SecretDetails,
  VulnerabilityDetails,
} from "./details/report-details";
import { WorkloadDetails } from "./details/workload-details";
import { TrivyIcon } from "./icons";
import {
  COMPLIANCE_PAGE_ID,
  MISCONFIGURATIONS_PAGE_ID,
  OVERVIEW_PAGE_ID,
  ROOT_MENU_ID,
  SBOMS_PAGE_ID,
  SECRETS_PAGE_ID,
  VULNERABILITIES_PAGE_ID,
} from "./navigation";
import { CompliancePage } from "./pages/compliance-page";
import { OverviewPage } from "./pages/overview-page";
import { MisconfigurationsPage, SbomsPage, SecretsPage, VulnerabilitiesPage } from "./pages/report-list-pages";

/** A page that shows the explanation instead of an error when the operator's CRDs are missing. */
const available = (kind: any, PageComponent: React.ComponentType<{ extension: Renderer.LensExtension }>) =>
  createAvailableVersionPage(kind.crd.title, [{ kubeObjectClass: kind, PageComponent, version: "v1alpha1" }]);

// Sidebar: one "Trivy Operator" root with the icon and six pages under it. `kind` is the CRD a page needs:
// without it the page explains that the operator is not installed.
const PAGES = [
  { id: OVERVIEW_PAGE_ID, title: "Overview", kind: VulnerabilityReport, Page: OverviewPage },
  { id: VULNERABILITIES_PAGE_ID, title: "Vulnerabilities", kind: VulnerabilityReport, Page: VulnerabilitiesPage },
  { id: MISCONFIGURATIONS_PAGE_ID, title: "Misconfigurations", kind: ConfigAuditReport, Page: MisconfigurationsPage },
  { id: SECRETS_PAGE_ID, title: "Secrets", kind: ExposedSecretReport, Page: SecretsPage },
  { id: SBOMS_PAGE_ID, title: "SBOM", kind: SbomReport, Page: SbomsPage },
  { id: COMPLIANCE_PAGE_ID, title: "Compliance", kind: ClusterComplianceReport, Page: CompliancePage },
];

const detailItem = (
  kinds: { kind: string; crd: { apiVersions: string[] } }[],
  Details: (
    props: Renderer.Component.KubeObjectDetailsProps<any> & { extension: Renderer.LensExtension },
  ) => JSX.Element,
  self: Renderer.LensExtension,
) =>
  kinds.map((k) => ({
    kind: k.kind,
    apiVersions: k.crd.apiVersions,
    priority: 10,
    components: {
      Details: (props: Renderer.Component.KubeObjectDetailsProps<any>) => <Details {...props} extension={self} />,
    },
  }));

/** Core kinds that get a "Trivy Operator" section, with the API group their objects are served from. */
const WORKLOAD_KINDS = [
  { kind: "Pod", apiVersions: ["v1"] },
  { kind: "ReplicaSet", apiVersions: ["apps/v1"] },
  { kind: "Deployment", apiVersions: ["apps/v1"] },
  { kind: "StatefulSet", apiVersions: ["apps/v1"] },
  { kind: "DaemonSet", apiVersions: ["apps/v1"] },
  { kind: "Job", apiVersions: ["batch/v1"] },
  { kind: "CronJob", apiVersions: ["batch/v1"] },
];

// Built once: a component created inside a render would remount on every render.
const AVAILABLE_PAGES = Object.fromEntries(PAGES.map((page) => [page.id, available(page.kind, page.Page)]));

export default class TrivyOperatorRenderer extends Renderer.LensExtension {
  // The host renders `Page` without props, so the extension is handed in here; the pages
  // need it for their links and for the error page.
  clusterPages = PAGES.map((page) => {
    const Available = AVAILABLE_PAGES[page.id];
    return { id: page.id, components: { Page: () => <Available extension={this} /> } };
  });

  clusterPageMenus = [
    {
      id: ROOT_MENU_ID,
      title: "Trivy Operator",
      target: { pageId: OVERVIEW_PAGE_ID },
      components: { Icon: TrivyIcon },
    },
    ...PAGES.map((page) => ({
      id: page.id,
      parentId: ROOT_MENU_ID,
      title: page.title,
      target: { pageId: page.id },
      components: {},
    })),
  ];

  kubeObjectDetailItems = [
    ...detailItem([VulnerabilityReport, ClusterVulnerabilityReport], VulnerabilityDetails, this),
    ...detailItem([ExposedSecretReport], SecretDetails, this),
    ...detailItem(
      [
        ConfigAuditReport,
        ClusterConfigAuditReport,
        RbacAssessmentReport,
        ClusterRbacAssessmentReport,
        InfraAssessmentReport,
        ClusterInfraAssessmentReport,
      ],
      ChecksDetails,
      this,
    ),
    ...detailItem([SbomReport, ClusterSbomReport], SbomDetails, this),
    ...detailItem([ClusterComplianceReport], ComplianceDetails, this),
    ...WORKLOAD_KINDS.map((k) => ({
      kind: k.kind,
      apiVersions: k.apiVersions,
      priority: 20,
      components: {
        Details: (props: Renderer.Component.KubeObjectDetailsProps<any>) => (
          <WorkloadDetails {...props} extension={this} />
        ),
      },
    })),
  ];
}
