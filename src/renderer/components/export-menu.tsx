// The Export button of a list: a menu of what to download. It exports what the list shows.

import { Renderer } from "@freelensapp/extensions";
import React from "react";
import { exportFileName, exportJson, exportTable, supportsFindings, toCsv } from "../api/trivy/export-model";
import { downloadText } from "./download";
import styles from "./export-menu.module.scss";
import stylesInline from "./export-menu.module.scss?inline";
import { activeClusterName, TICK_HINT } from "./rescan-ui";

interface Item {
  kind?: string;
  metadata?: any;
  report?: any;
}

type Choice = "reports-csv" | "findings-csv" | "json";

export function ExportMenu(props: {
  /** The ticked reports that are on screen: what an export writes. */
  items: Item[];
  /** What the list is called in the file name, such as "Vulnerabilities". */
  title: string;
}) {
  const [open, setOpen] = React.useState(false);
  const root = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (!open) return;
    const away = (event: MouseEvent) => {
      if (root.current && !root.current.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [open]);

  const run = (choice: Choice) => {
    setOpen(false);
    const { Notifications } = Renderer.Component;
    const { items } = props;
    if (items.length === 0) {
      Notifications.info("Nothing to export: tick workloads first.");
      return;
    }
    const cluster = activeClusterName();
    const now = new Date();
    const noun = items.length === 1 ? "report" : "reports";
    let name: string;
    if (choice === "json") {
      name = exportFileName(props.title, cluster, now, "json");
      downloadText(name, exportJson(items, { cluster, when: now }), "application/json");
    } else {
      const mode = choice === "findings-csv" ? "findings" : "reports";
      const { columns, rows } = exportTable(items, mode);
      name = exportFileName(props.title, cluster, now, "csv", mode === "findings" ? "findings" : undefined);
      downloadText(name, toCsv(columns, rows), "text/csv");
    }
    Notifications.ok(`Exported ${items.length} ${noun} as ${name}`);
  };

  const count = props.items.length;
  const off = count === 0;
  const findings = supportsFindings(props.items[0]?.kind);

  return (
    <div
      className={styles.root}
      ref={root}
      onKeyDown={(event) => {
        if (event.key === "Escape") setOpen(false);
      }}
    >
      <style>{stylesInline}</style>
      <span title={off ? TICK_HINT : "Download the ticked reports"}>
        <button
          type="button"
          className={styles.button}
          aria-haspopup="menu"
          aria-expanded={open}
          disabled={off}
          onClick={() => setOpen(!open)}
        >
          {off ? "Export" : `Export ${count}`} <span aria-hidden="true">▾</span>
        </button>
      </span>
      {open && !off ? (
        <div className={styles.menu} role="menu">
          <div className={styles.scope}>
            <b>
              {count} ticked {count === 1 ? "workload" : "workloads"}
            </b>
            <small>same ticks as Rescan</small>
          </div>
          <button type="button" role="menuitem" className={styles.item} onClick={() => run("reports-csv")}>
            Reports <small>CSV · one row per report</small>
          </button>
          {findings ? (
            <button type="button" role="menuitem" className={styles.item} onClick={() => run("findings-csv")}>
              Findings <small>CSV · one row per finding</small>
            </button>
          ) : null}
          <button type="button" role="menuitem" className={styles.item} onClick={() => run("json")}>
            JSON <small>reports with their findings</small>
          </button>
        </div>
      ) : null}
    </div>
  );
}
