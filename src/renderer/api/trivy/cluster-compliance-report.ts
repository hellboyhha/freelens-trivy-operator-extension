import { Renderer } from "@freelensapp/extensions";
import { type ComplianceSpec, type ComplianceStatus, TRIVY_API_VERSION, trivyCrd } from "./common";

import type { TrivyKubeObjectCRD } from "../types";

export class ClusterComplianceReport extends Renderer.K8sApi.LensExtensionKubeObject<
  Renderer.K8sApi.KubeObjectMetadata,
  ComplianceStatus,
  ComplianceSpec
> {
  static readonly kind = "ClusterComplianceReport";
  static readonly namespaced = false;
  static readonly apiBase = `/apis/${TRIVY_API_VERSION}/clustercompliancereports`;

  static readonly crd: TrivyKubeObjectCRD = trivyCrd(
    "clustercompliancereports",
    "clustercompliancereport",
    ["compliance"],
    "Compliance",
  );
}

export class ClusterComplianceReportApi extends Renderer.K8sApi.KubeApi<ClusterComplianceReport> {}
