import { Renderer } from "@freelensapp/extensions";
import { TrivyIcon } from "./icons";
import { OverviewPage } from "./pages/overview-page";

export default class TrivyOperatorRenderer extends Renderer.LensExtension {
  clusterPages = [
    {
      id: "trivy",
      components: {
        Page: () => <OverviewPage extension={this} />,
      },
    },
  ];

  clusterPageMenus = [
    {
      id: "trivy",
      title: "Trivy",
      target: { pageId: "trivy" },
      components: {
        Icon: TrivyIcon,
      },
    },
  ];
}
