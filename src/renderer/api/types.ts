import { Renderer } from "@freelensapp/extensions";

/** CRD descriptor of the Trivy Operator kinds: the host shape plus the page title. */
export interface TrivyKubeObjectCRD extends Renderer.K8sApi.LensExtensionKubeObjectCRD {
  title: string;
}
