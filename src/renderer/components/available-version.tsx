import { Common, Renderer } from "@freelensapp/extensions";
import { CodeBlock, EmptyState, Muted, UiStyles } from "./ui";

const LOG_PREFIX = "[trivy-operator-extension]";

export interface AvailableVersionPageProps {
  extension: Renderer.LensExtension;
}

/** One API version of a kind, with the page that renders it. */
interface VersionVariant<T extends AvailableVersionPageProps> {
  kubeObjectClass: typeof Renderer.K8sApi.LensExtensionKubeObject<any, any, any>;
  PageComponent: React.ComponentType<T>;
  version: string;
}

const INSTALL = `helm repo add aqua https://aquasecurity.github.io/helm-charts/
helm install trivy-operator aqua/trivy-operator -n trivy-system --create-namespace`;

/**
 * Creates a page that renders the first API version the cluster serves, and an
 * explanation instead of a crash when the Trivy Operator CRDs are not installed.
 * Variants are tried in order of preference.
 */
export function createAvailableVersionPage<T extends AvailableVersionPageProps>(
  resourceName: string,
  variants: VersionVariant<T>[],
): React.ComponentType<T> {
  return (props: T) => {
    for (const variant of variants) {
      try {
        const store = variant.kubeObjectClass.getStore();
        if (store) {
          Common.logger.debug(`${LOG_PREFIX}: Rendering ${resourceName} page with API version ${variant.version}`);
          return <variant.PageComponent {...props} />;
        }
      } catch (error) {
        Common.logger.debug(
          `${LOG_PREFIX}: API version ${variant.version} not available for ${resourceName}: ${error}`,
        );
      }
    }

    const triedVersions = variants.map((v) => v.version).join(", ");
    Common.logger.info(`${LOG_PREFIX}: ${resourceName} CRD not found in cluster (tried versions: ${triedVersions})`);

    return (
      <>
        <UiStyles />
        <EmptyState title="Trivy Operator is not installed in this cluster">
          <p>
            The <strong>{resourceName}</strong> reports come from the Trivy Operator, and its CRDs are not in this
            cluster. Install it and the reports appear here within minutes.
          </p>
          <CodeBlock>{INSTALL}</CodeBlock>
          <Muted>Tried API versions: {triedVersions}.</Muted>
        </EmptyState>
      </>
    );
  };
}
