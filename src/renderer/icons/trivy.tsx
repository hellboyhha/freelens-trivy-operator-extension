import { Renderer } from "@freelensapp/extensions";
import svgIcon from "./trivy.svg?raw";

const {
  Component: { Icon },
} = Renderer;

export function TrivyIcon(props: Renderer.Component.IconProps) {
  return <Icon {...props} svg={svgIcon} />;
}
