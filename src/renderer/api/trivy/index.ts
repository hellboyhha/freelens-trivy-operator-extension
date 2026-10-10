import { ClusterComplianceReport } from "./cluster-compliance-report";
import { ClusterConfigAuditReport, ConfigAuditReport } from "./config-audit-report";
import { ExposedSecretReport } from "./exposed-secret-report";
import { ClusterInfraAssessmentReport, InfraAssessmentReport } from "./infra-assessment-report";
import { ClusterRbacAssessmentReport, RbacAssessmentReport } from "./rbac-assessment-report";
import { ClusterSbomReport, SbomReport } from "./sbom-report";
import { ClusterVulnerabilityReport, VulnerabilityReport } from "./vulnerability-report";

export {
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
};

/** Every kind the extension reads. */
export const ALL_REPORT_KINDS = [
  VulnerabilityReport,
  ClusterVulnerabilityReport,
  ExposedSecretReport,
  ConfigAuditReport,
  ClusterConfigAuditReport,
  RbacAssessmentReport,
  ClusterRbacAssessmentReport,
  InfraAssessmentReport,
  ClusterInfraAssessmentReport,
  SbomReport,
  ClusterSbomReport,
  ClusterComplianceReport,
] as const;
