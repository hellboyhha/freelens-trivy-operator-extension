import { withErrorPage } from "../components/error-page";

import type { Renderer } from "@freelensapp/extensions";

export interface OverviewPageProps {
  extension: Renderer.LensExtension;
}

export const OverviewPage = (props: OverviewPageProps) =>
  withErrorPage(props, () => (
    <div style={{ padding: 16 }}>
      <h2>Trivy Operator</h2>
      <p>Scaffold only. Report pages arrive in the next releases.</p>
    </div>
  ));
