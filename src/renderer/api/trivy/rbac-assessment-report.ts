import { Renderer } from "@freelensapp/extensions";
import { type ChecksReportData, TRIVY_API_VERSION, trivyCrd } from "./common";

import type { TrivyKubeObjectCRD } from "../types";

export class RbacAssessmentReport extends Renderer.K8sApi.LensExtensionKubeObject<
  Renderer.K8sApi.KubeObjectMetadata,
  Record<string, never>,
  Record<string, never>
> {
  static readonly kind = "RbacAssessmentReport";
  static readonly namespaced = true;
  static readonly apiBase = `/apis/${TRIVY_API_VERSION}/rbacassessmentreports`;

  static readonly crd: TrivyKubeObjectCRD = trivyCrd(
    "rbacassessmentreports",
    "rbacassessmentreport",
    ["rbacassessment", "rbacassessments"],
    "RBAC Assessment",
  );

  // Declared, not initialized: the host assigns the raw JSON in the constructor and a
  // class field with an initializer would overwrite it with undefined.
  declare report?: ChecksReportData;
}

export class RbacAssessmentReportApi extends Renderer.K8sApi.KubeApi<RbacAssessmentReport> {}

export class ClusterRbacAssessmentReport extends Renderer.K8sApi.LensExtensionKubeObject<
  Renderer.K8sApi.KubeObjectMetadata,
  Record<string, never>,
  Record<string, never>
> {
  static readonly kind = "ClusterRbacAssessmentReport";
  static readonly namespaced = false;
  static readonly apiBase = `/apis/${TRIVY_API_VERSION}/clusterrbacassessmentreports`;

  static readonly crd: TrivyKubeObjectCRD = trivyCrd(
    "clusterrbacassessmentreports",
    "clusterrbacassessmentreport",
    ["clusterrbacassessmentreport"],
    "Cluster RBAC Assessment",
  );

  // Declared, not initialized: the host assigns the raw JSON in the constructor and a
  // class field with an initializer would overwrite it with undefined.
  declare report?: ChecksReportData;
}

export class ClusterRbacAssessmentReportApi extends Renderer.K8sApi.KubeApi<ClusterRbacAssessmentReport> {}
