import { Renderer } from "@freelensapp/extensions";
import { type ChecksReportData, TRIVY_API_VERSION, trivyCrd } from "./common";

import type { TrivyKubeObjectCRD } from "../types";

export class InfraAssessmentReport extends Renderer.K8sApi.LensExtensionKubeObject<
  Renderer.K8sApi.KubeObjectMetadata,
  Record<string, never>,
  Record<string, never>
> {
  static readonly kind = "InfraAssessmentReport";
  static readonly namespaced = true;
  static readonly apiBase = `/apis/${TRIVY_API_VERSION}/infraassessmentreports`;

  static readonly crd: TrivyKubeObjectCRD = trivyCrd(
    "infraassessmentreports",
    "infraassessmentreport",
    ["infraassessment", "infraassessments"],
    "Infra Assessment",
  );

  // Declared, not initialized: the host assigns the raw JSON in the constructor and a
  // class field with an initializer would overwrite it with undefined.
  declare report?: ChecksReportData;
}

export class InfraAssessmentReportApi extends Renderer.K8sApi.KubeApi<InfraAssessmentReport> {}

export class ClusterInfraAssessmentReport extends Renderer.K8sApi.LensExtensionKubeObject<
  Renderer.K8sApi.KubeObjectMetadata,
  Record<string, never>,
  Record<string, never>
> {
  static readonly kind = "ClusterInfraAssessmentReport";
  static readonly namespaced = false;
  static readonly apiBase = `/apis/${TRIVY_API_VERSION}/clusterinfraassessmentreports`;

  static readonly crd: TrivyKubeObjectCRD = trivyCrd(
    "clusterinfraassessmentreports",
    "clusterinfraassessmentreport",
    ["clusterinfraassessment"],
    "Cluster Infra Assessment",
  );

  // Declared, not initialized: the host assigns the raw JSON in the constructor and a
  // class field with an initializer would overwrite it with undefined.
  declare report?: ChecksReportData;
}

export class ClusterInfraAssessmentReportApi extends Renderer.K8sApi.KubeApi<ClusterInfraAssessmentReport> {}
