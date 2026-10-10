// Types written from the aquasecurity.github.io/v1alpha1 CRDs of Trivy Operator
// (checked against v0.31.2 reports). The operator writes the findings under
// `.report`, not under `spec` or `status`, except for ClusterComplianceReport.
//
// Every field is optional: the operator omits empty ones and older versions
// write fewer fields.

import type { TrivyKubeObjectCRD } from "../types";

export const TRIVY_API_VERSION = "aquasecurity.github.io/v1alpha1";

export function trivyCrd(plural: string, singular: string, shortNames: string[], title: string): TrivyKubeObjectCRD {
  return { apiVersions: [TRIVY_API_VERSION], plural, singular, shortNames, title };
}

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN" | "NONE";

export interface Scanner {
  name?: string;
  vendor?: string;
  version?: string;
}

export interface Artifact {
  repository?: string;
  tag?: string;
  digest?: string;
}

export interface Registry {
  server?: string;
}

export interface OsInfo {
  family?: string;
  name?: string;
  eosl?: boolean;
}

/** Counts of the checks and secrets that failed, by severity. */
export interface SeveritySummary {
  criticalCount?: number;
  highCount?: number;
  mediumCount?: number;
  lowCount?: number;
  unknownCount?: number;
  noneCount?: number;
}

export interface Vulnerability {
  vulnerabilityID?: string;
  resource?: string;
  installedVersion?: string;
  fixedVersion?: string;
  severity?: Severity;
  score?: number;
  title?: string;
  primaryLink?: string;
  links?: string[];
  target?: string;
  packagePURL?: string;
  publishedDate?: string;
  lastModifiedDate?: string;
}

export interface VulnerabilityReportData {
  artifact?: Artifact;
  registry?: Registry;
  os?: OsInfo;
  scanner?: Scanner;
  summary?: SeveritySummary;
  updateTimestamp?: string;
  vulnerabilities?: Vulnerability[];
}

export interface Check {
  checkID?: string;
  title?: string;
  description?: string;
  category?: string;
  severity?: Severity;
  success?: boolean;
  messages?: string[];
  remediation?: string;
}

export interface ChecksReportData {
  scanner?: Scanner;
  summary?: SeveritySummary;
  updateTimestamp?: string;
  checks?: Check[];
}

export interface ExposedSecret {
  ruleID?: string;
  title?: string;
  category?: string;
  severity?: Severity;
  target?: string;
  /** The operator masks the matched text with asterisks. */
  match?: string;
}

export interface ExposedSecretReportData {
  artifact?: Artifact;
  registry?: Registry;
  scanner?: Scanner;
  summary?: SeveritySummary;
  updateTimestamp?: string;
  secrets?: ExposedSecret[];
}

export interface SbomComponent {
  "bom-ref"?: string;
  name?: string;
  version?: string;
  type?: string;
  purl?: string;
}

export interface SbomDependency {
  ref?: string;
  dependsOn?: string[];
}

/** The CycloneDX document the operator embeds in the report. */
export interface CycloneDx {
  bomFormat?: string;
  specVersion?: string;
  serialNumber?: string;
  version?: number;
  components?: SbomComponent[];
  dependencies?: SbomDependency[];
}

export interface SbomReportData {
  artifact?: Artifact;
  registry?: Registry;
  scanner?: Scanner;
  summary?: { componentsCount?: number; dependenciesCount?: number };
  updateTimestamp?: string;
  components?: CycloneDx;
}

export interface ComplianceControl {
  id?: string;
  name?: string;
  description?: string;
  severity?: Severity;
  checks?: { id?: string }[];
  commands?: { id?: string }[];
}

export interface ComplianceSpec {
  cron?: string;
  reportType?: "summary" | "all";
  compliance?: {
    id?: string;
    title?: string;
    description?: string;
    version?: string;
    platform?: string;
    type?: string;
    relatedResources?: string[];
    controls?: ComplianceControl[];
  };
}

export interface ComplianceStatus {
  updateTimestamp?: string;
  summary?: { failCount?: number; passCount?: number };
  summaryReport?: {
    id?: string;
    title?: string;
    controlCheck?: { id?: string; name?: string; severity?: Severity; totalFail?: number }[];
  };
}
