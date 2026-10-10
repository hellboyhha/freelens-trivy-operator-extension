// The frame of a report page: an optional row above (tabs) and the list below it, spaced by one step.

import styles from "./report-list.module.scss";
import stylesInline from "./report-list.module.scss?inline";
import { UiStyles } from "./ui";

export function PageFrame(props: { head?: React.ReactNode; children: React.ReactNode }) {
  return (
    <>
      <style>{stylesInline}</style>
      <UiStyles />
      <div className={styles.frame}>
        {props.head}
        <div className={styles.frameBody}>{props.children}</div>
      </div>
    </>
  );
}

/** Puts its content in the middle of the page, horizontally and vertically. */
export function Centered(props: { children: React.ReactNode }) {
  return <div className={styles.centered}>{props.children}</div>;
}
