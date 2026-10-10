import { Renderer } from "@freelensapp/extensions";
import { type ChecksReportData, TRIVY_API_VERSION, trivyCrd } from "./common";

import type { TrivyKubeObjectCRD } from "../types";

export class ConfigAuditReport extends Renderer.K8sApi.LensExtensionKubeObject<
  Renderer.K8sApi.KubeObjectMetadata,
  Record<string, never>,
  Record<string, never>
> {
  static readonly kind = "ConfigAuditReport";
  static readonly namespaced = true;
  static readonly apiBase = `/apis/${TRIVY_API_VERSION}/configauditreports`;

  static readonly crd: TrivyKubeObjectCRD = trivyCrd(
    "configauditreports",
    "configauditreport",
    ["configaudit", "configaudits"],
    "Config Audit",
  );

  // Declared, not initialized: the host assigns the raw JSON in the constructor and a
  // class field with an initializer would overwrite it with undefined.
  declare report?: ChecksReportData;
}

export class ConfigAuditReportApi extends Renderer.K8sApi.KubeApi<ConfigAuditReport> {}

export class ClusterConfigAuditReport extends Renderer.K8sApi.LensExtensionKubeObject<
  Renderer.K8sApi.KubeObjectMetadata,
  Record<string, never>,
  Record<string, never>
> {
  static readonly kind = "ClusterConfigAuditReport";
  static readonly namespaced = false;
  static readonly apiBase = `/apis/${TRIVY_API_VERSION}/clusterconfigauditreports`;

  static readonly crd: TrivyKubeObjectCRD = trivyCrd(
    "clusterconfigauditreports",
    "clusterconfigauditreport",
    ["clusterconfigaudit"],
    "Cluster Config Audit",
  );

  // Declared, not initialized: the host assigns the raw JSON in the constructor and a
  // class field with an initializer would overwrite it with undefined.
  declare report?: ChecksReportData;
}

export class ClusterConfigAuditReportApi extends Renderer.K8sApi.KubeApi<ClusterConfigAuditReport> {}
