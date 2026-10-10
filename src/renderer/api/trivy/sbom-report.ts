import { Renderer } from "@freelensapp/extensions";
import { type SbomReportData, TRIVY_API_VERSION, trivyCrd } from "./common";

import type { TrivyKubeObjectCRD } from "../types";

export class SbomReport extends Renderer.K8sApi.LensExtensionKubeObject<
  Renderer.K8sApi.KubeObjectMetadata,
  Record<string, never>,
  Record<string, never>
> {
  static readonly kind = "SbomReport";
  static readonly namespaced = true;
  static readonly apiBase = `/apis/${TRIVY_API_VERSION}/sbomreports`;

  static readonly crd: TrivyKubeObjectCRD = trivyCrd("sbomreports", "sbomreport", ["sbom", "sboms"], "SBOM");

  // Declared, not initialized: the host assigns the raw JSON in the constructor and a
  // class field with an initializer would overwrite it with undefined.
  declare report?: SbomReportData;
}

export class SbomReportApi extends Renderer.K8sApi.KubeApi<SbomReport> {}

export class ClusterSbomReport extends Renderer.K8sApi.LensExtensionKubeObject<
  Renderer.K8sApi.KubeObjectMetadata,
  Record<string, never>,
  Record<string, never>
> {
  static readonly kind = "ClusterSbomReport";
  static readonly namespaced = false;
  static readonly apiBase = `/apis/${TRIVY_API_VERSION}/clustersbomreports`;

  static readonly crd: TrivyKubeObjectCRD = trivyCrd(
    "clustersbomreports",
    "clustersbomreport",
    ["clustersbom"],
    "Cluster SBOM",
  );

  // Declared, not initialized: the host assigns the raw JSON in the constructor and a
  // class field with an initializer would overwrite it with undefined.
  declare report?: SbomReportData;
}

export class ClusterSbomReportApi extends Renderer.K8sApi.KubeApi<ClusterSbomReport> {}
