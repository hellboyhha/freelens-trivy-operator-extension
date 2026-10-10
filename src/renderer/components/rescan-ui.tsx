// The pieces of Rescan the user sees: the bar above the list, the confirmation, the row that waits
// for the operator, and the hook that keeps those rows in step with the store.

import { Renderer } from "@freelensapp/extensions";
import React from "react";
import { maybe } from "../../common/utils";
import { imageOf, resourceOf } from "../api/trivy/report-model";
import { type RemovableStore, rescanAcross } from "../api/trivy/rescan";
import {
  type ConfirmPlan,
  confirmPlan,
  describeOutcome,
  ghostItems,
  isConfirmed,
  type OutcomeMessage,
  type Pending,
  type ReportLike,
  type WorkloadRef,
} from "../api/trivy/rescan-model";
import { rescanTracker } from "../api/trivy/rescan-tracker";
import { describeScan } from "../api/trivy/scan-status-model";
import styles from "./rescan-ui.module.scss";
import stylesInline from "./rescan-ui.module.scss?inline";

/** Render once where the bar, dialog or pill is used so the classes exist. */
export function RescanStyles() {
  return <style>{stylesInline}</style>;
}

/** The name of the cluster open in this window; empty when Freelens does not say. */
export function activeClusterName(): string {
  return maybe(() => Renderer.Catalog.catalogEntities.activeEntity?.getName()) ?? "";
}

/** Shows each message the way Freelens shows notifications. */
export function notify(messages: OutcomeMessage[]): void {
  const { Notifications } = Renderer.Component;
  for (const message of messages) Notifications[message.tone](message.text);
}

/** Why the toolbar's Rescan and Export are off before anything is ticked. */
export const TICK_HINT = "Tick workloads to rescan or export";

/** Rescan in the toolbar: always there, off until something is ticked, then "Rescan N". */
export function RescanToolbarButton(props: { count: number; onClick: () => void }) {
  const off = props.count === 0;
  const button = (
    <button
      type="button"
      className={`${styles.tool} ${off ? "" : styles.primary}`}
      disabled={off}
      onClick={props.onClick}
      title={off ? undefined : "Delete the selected reports so the Trivy Operator scans their workloads again"}
    >
      <span aria-hidden="true">↻</span> {off ? "Rescan" : `Rescan ${props.count}`}
    </button>
  );
  // A disabled button shows no tooltip of its own, so the hint sits on a wrapper.
  return off ? <span title={TICK_HINT}>{button}</span> : button;
}

export type DialogItem = ReportLike & { report?: { artifact?: Parameters<typeof imageOf>[0] } };

/** Names the cluster and what will happen, and for several reports asks for the cluster's name. */
export function RescanDialog(props: {
  items: DialogItem[];
  plan: ConfirmPlan;
  clusterName: string;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const { items, plan, busy } = props;
  const [typed, setTyped] = React.useState("");
  const oneReport = plan.count === 1;
  const single = oneReport || !!plan.workload;
  const confirmed = isConfirmed(plan, typed) && !busy;
  const ref = plan.workload ?? (oneReport ? resourceOf(items[0].metadata) : undefined);
  const container = oneReport ? resourceOf(items[0].metadata).container : undefined;
  const image = oneReport ? imageOf(items[0].report?.artifact) : "";

  return (
    <div
      className={styles.overlay}
      onKeyDown={(event) => {
        if (event.key === "Escape") props.onCancel();
      }}
    >
      <div className={styles.dialog} role="dialog" aria-modal="true" aria-labelledby="rescan-title">
        <h4 id="rescan-title">{single ? "Rescan this workload?" : `Rescan ${plan.count} workloads?`}</h4>
        <p>
          {oneReport
            ? "The report is deleted and the Trivy Operator scans the workload again."
            : plan.workload
              ? `${plan.count} reports are deleted and the Trivy Operator scans the workload again.`
              : `${plan.count} reports are deleted and ${plan.count} scans start. On a busy cluster they queue and use CPU and bandwidth to download images.`}
        </p>
        <dl className={styles.facts}>
          <dt>Cluster</dt>
          <dd>{props.clusterName || "unknown"}</dd>
          {single && ref ? (
            <>
              <dt>Workload</dt>
              <dd>{[ref.namespace, ref.kind, ref.name].filter(Boolean).join(" / ")}</dd>
              {container ? (
                <>
                  <dt>Container</dt>
                  <dd>{container}</dd>
                </>
              ) : null}
              {plan.workload ? (
                <>
                  <dt>Reports</dt>
                  <dd>{plan.count}</dd>
                </>
              ) : null}
              {image ? (
                <>
                  <dt>Image</dt>
                  <dd>{image}</dd>
                </>
              ) : null}
            </>
          ) : (
            <>
              <dt>Namespaces</dt>
              <dd>{plan.namespaces.join(", ")}</dd>
              <dt>Reports</dt>
              <dd>
                <details>
                  <summary>{plan.count}</summary>
                  <ul className={styles.list}>
                    {items.map((item) => (
                      <li key={`${item.kind}/${item.metadata.namespace}/${item.metadata.name}`}>
                        {resourceOf(item.metadata).name || item.metadata.name}
                      </li>
                    ))}
                  </ul>
                </details>
              </dd>
            </>
          )}
        </dl>
        {single ? (
          <p className={styles.note}>
            {oneReport ? "The report disappears" : "The reports disappear"} from the lists for a few minutes while the
            new scan runs. Nothing else in the cluster changes.
          </p>
        ) : (
          <>
            <p className={styles.note}>
              Type <b>{plan.phrase}</b> to confirm:
            </p>
            <input
              className={styles.typed}
              type="text"
              value={typed}
              autoFocus
              aria-label="Type to confirm"
              onChange={(event) => setTyped(event.target.value)}
            />
          </>
        )}
        <div className={styles.actions}>
          <button type="button" className={styles.button} onClick={props.onCancel} autoFocus={single}>
            Cancel
          </button>
          <button
            type="button"
            className={`${styles.button} ${styles.primary}`}
            disabled={!confirmed}
            onClick={props.onConfirm}
          >
            {single ? "Rescan" : `Rescan ${plan.count}`}
          </button>
        </div>
      </div>
    </div>
  );
}

/** The cell of a row whose report is being replaced: what the scan is doing, and why if it failed. */
export function RescanPill({ pending, now }: { pending: Pending<ReportLike>; now: number }) {
  const scan = describeScan(pending, now);
  const tone = scan.tone === "error" ? styles.failed : scan.tone === "warn" ? styles.stale : "";
  return (
    <span className={styles.status} title={scan.title}>
      <span className={`${styles.pill} ${tone}`}>
        {scan.tone === "busy" ? <i className={styles.spinner} /> : null}
        {scan.text}
      </span>
      {scan.note ? <span className={styles.statusNote}>{scan.note}</span> : null}
    </span>
  );
}

/**
 * The waiting rows of one kind of report, kept current: a wait ends when the operator's new report
 * appears in `items`, and the elapsed time moves every 15 seconds.
 */
export function useRescanTracker<T extends ReportLike>(kind: string, items: T[]) {
  const [, rerender] = React.useReducer((n: number) => n + 1, 0);
  React.useEffect(() => rescanTracker.subscribe(rerender), []);
  const waiting = rescanTracker.list().filter((p) => p.item.kind === kind);
  React.useEffect(() => {
    rescanTracker.reconcile(items);
  });
  React.useEffect(() => {
    if (waiting.length === 0) return;
    const timer = setInterval(rerender, 15_000);
    return () => clearInterval(timer);
  }, [waiting.length]);
  return { waiting, ghosts: ghostItems(waiting, items) as T[], now: Date.now() };
}

type RescanItem = DialogItem;

/**
 * Asking, confirming and deleting, for any place that offers Rescan. `ask` opens the confirmation for
 * the given reports; `dialog` is what to render. `storeOf` says which store deletes a report, so one
 * request can span several kinds.
 */
export function useRescan<T extends RescanItem>(
  storeOf: (item: T) => RemovableStore<T> | undefined,
  options: { after?: () => void } = {},
) {
  const [asked, setAsked] = React.useState<{ items: T[]; workload?: WorkloadRef } | null>(null);
  const [busy, setBusy] = React.useState(false);

  const confirm = async () => {
    if (!asked) return;
    setBusy(true);
    try {
      const result = await rescanAcross(storeOf, asked.items);
      rescanTracker.add([...result.requested, ...result.gone]);
      notify(describeOutcome(result));
      options.after?.();
    } finally {
      setBusy(false);
      setAsked(null);
    }
  };

  const clusterName = activeClusterName();
  const dialog = asked ? (
    <RescanDialog
      items={asked.items}
      plan={confirmPlan(asked.items, clusterName, asked.workload)}
      clusterName={clusterName}
      busy={busy}
      onCancel={() => setAsked(null)}
      onConfirm={confirm}
    />
  ) : null;

  return { ask: (items: T[], workload?: WorkloadRef) => setAsked({ items, workload }), dialog, busy };
}

/** The Rescan button of a drawer: a small outlined button with the dialog it opens. */
export function RescanButton(props: { onClick: () => void; disabled?: boolean; label?: string; title?: string }) {
  return (
    <button
      type="button"
      className={styles.button}
      onClick={props.onClick}
      disabled={props.disabled}
      title={props.title ?? "Delete the report so the Trivy Operator scans the workload again"}
    >
      <span aria-hidden="true">↻</span> {props.label ?? "Rescan"}
    </button>
  );
}
