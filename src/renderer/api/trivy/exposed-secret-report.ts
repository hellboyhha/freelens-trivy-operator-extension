import { Renderer } from "@freelensapp/extensions";
import { type ExposedSecretReportData, TRIVY_API_VERSION, trivyCrd } from "./common";

import type { TrivyKubeObjectCRD } from "../types";

export class ExposedSecretReport extends Renderer.K8sApi.LensExtensionKubeObject<
  Renderer.K8sApi.KubeObjectMetadata,
  Record<string, never>,
  Record<string, never>
> {
  static readonly kind = "ExposedSecretReport";
  static readonly namespaced = true;
  static readonly apiBase = `/apis/${TRIVY_API_VERSION}/exposedsecretreports`;

  static readonly crd: TrivyKubeObjectCRD = trivyCrd(
    "exposedsecretreports",
    "exposedsecretreport",
    ["exposedsecret", "exposedsecrets"],
    "Exposed Secrets",
  );

  // Declared, not initialized: the host assigns the raw JSON in the constructor and a
  // class field with an initializer would overwrite it with undefined.
  declare report?: ExposedSecretReportData;
}

export class ExposedSecretReportApi extends Renderer.K8sApi.KubeApi<ExposedSecretReport> {}
