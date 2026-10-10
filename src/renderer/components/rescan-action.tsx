// Rescan as a button in a drawer: for one report (its own drawer) or for a workload's reports (the
// Trivy Operator section on the workload's page).

import React from "react";
import { maybe } from "../../common/utils";
import { keyOf, type WorkloadRef } from "../api/trivy/rescan-model";
import { rescanTracker } from "../api/trivy/rescan-tracker";
import { type DialogItem, RescanButton, RescanPill, RescanStyles, useRescan } from "./rescan-ui";
import styles from "./rescan-ui.module.scss";

type Item = DialogItem;

/** The deleting store of a report, which its class provides. */
const storeOfItem = (item: Item) => maybe(() => (item.constructor as unknown as { getStore(): any }).getStore());

/** The reports of `items` that are waiting for a new scan. */
function useWaiting(items: Item[]) {
  const [, rerender] = React.useReducer((n: number) => n + 1, 0);
  React.useEffect(() => rescanTracker.subscribe(rerender), []);
  const keys = new Set(items.map(keyOf));
  return rescanTracker.list().filter((p) => keys.has(p.key));
}

/**
 * Nothing is shown when there is nothing to rescan or the cluster has no store for the report's kind.
 * While a scan is under way the button gives way to its state.
 */
export function RescanAction(props: {
  items: Item[];
  /** Set on a workload's page, where all its reports are one request with one confirmation. */
  workload?: WorkloadRef;
  /** Run after the reports were deleted, for example to close the drawer of a report that is gone. */
  after?: () => void;
  label?: string;
}) {
  const rescan = useRescan<Item>(storeOfItem, { after: props.after });
  const waiting = useWaiting(props.items);
  if (props.items.length === 0 || props.items.some((i) => !storeOfItem(i))) return null;
  return (
    <div className={styles.drawerAction}>
      <RescanStyles />
      {waiting.length > 0 ? (
        <RescanPill pending={waiting[0]} now={Date.now()} />
      ) : (
        <RescanButton label={props.label} onClick={() => rescan.ask(props.items, props.workload)} />
      )}
      {rescan.dialog}
    </div>
  );
}
