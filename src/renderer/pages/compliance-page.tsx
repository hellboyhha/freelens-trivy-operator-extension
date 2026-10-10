// Compliance: one card per benchmark and, for the one selected, its controls with the
// failing ones first.

import { Renderer } from "@freelensapp/extensions";
import * as MobxReact from "mobx-react";
import React from "react";
import { maybe } from "../../common/utils";
import { ClusterComplianceReport } from "../api/trivy";
import { withErrorPage } from "../components/error-page";
import { formatAge } from "../components/format";
import { SeverityCount, SeverityLabel, SeverityStyles } from "../components/severity-count";
import { Chips, EmptyState, Muted, PassFailBar, Skeleton, UiStyles } from "../components/ui";
import { type LoadableStore, useLoadedStores } from "../components/use-loaded-stores";
import styles from "./compliance-page.module.scss";
import stylesInline from "./compliance-page.module.scss?inline";

const { observer } = MobxReact;

const {
  Component: { Table, TableCell, TableHead, TableRow, TabLayout, WithTooltip },
} = Renderer;

export interface CompliancePageProps {
  extension: Renderer.LensExtension;
}

interface StoreLike extends LoadableStore {
  contextItems: any[];
}

export const CompliancePage = observer((props: CompliancePageProps) =>
  withErrorPage(props, () => {
    const [chosen, setChosen] = React.useState<string | undefined>();
    const [onlyFailing, setOnlyFailing] = React.useState(true);
    const [search, setSearch] = React.useState("");

    const store = maybe(() => ClusterComplianceReport.getStore()) as StoreLike | null;
    useLoadedStores([{ label: "compliance", store }]);

    const loading = !store?.isLoaded && !store?.failedLoading;
    const reports = (store?.contextItems ?? [])
      .slice()
      .sort(
        (a, b) =>
          (b.status?.summary?.failCount ?? 0) - (a.status?.summary?.failCount ?? 0) ||
          a.getName().localeCompare(b.getName()),
      );
    const selected = reports.find((r) => r.getName() === chosen) ?? reports[0];

    const controls = new Map<string, { description?: string }>(
      (selected?.spec?.compliance?.controls ?? []).map((c: any) => [c.id, c]),
    );
    const needle = search.trim().toLowerCase();
    const rows = ((selected?.status?.summaryReport?.controlCheck ?? []) as any[])
      .filter((r) => (onlyFailing ? (r.totalFail ?? 0) > 0 : true))
      .filter((r) => !needle || `${r.id} ${r.name}`.toLowerCase().includes(needle))
      .sort(
        (a, b) =>
          (b.totalFail ?? 0) - (a.totalFail ?? 0) ||
          String(a.id).localeCompare(String(b.id), undefined, { numeric: true }),
      );

    return (
      <TabLayout scrollable>
        <UiStyles />
        <SeverityStyles />
        <style>{stylesInline}</style>
        <div className={styles.page}>
          <h5 className={styles.title}>Compliance</h5>
          {loading ? (
            <Skeleton count={3} />
          ) : reports.length === 0 ? (
            <EmptyState title="No compliance reports yet">
              <p>
                The operator writes them on a schedule (every six hours by default). Check back after its first run.
              </p>
            </EmptyState>
          ) : (
            <>
              <div className={styles.cards}>
                {reports.map((report) => {
                  const failing = report.status?.summary?.failCount ?? 0;
                  const passing = report.status?.summary?.passCount ?? 0;
                  const share = failing + passing > 0 ? Math.round((passing / (failing + passing)) * 100) : 0;
                  return (
                    <button
                      key={report.getName()}
                      type="button"
                      className={[styles.card, report === selected ? styles.cardOn : ""].join(" ")}
                      onClick={() => setChosen(report.getName())}
                    >
                      <span className={styles.cardTitle}>{report.spec?.compliance?.title ?? report.getName()}</span>
                      <span className={styles.cardFailing}>
                        {failing}
                        <span className={styles.cardUnit}>failing</span>
                      </span>
                      <PassFailBar passing={passing} failing={failing} />
                      <span className={styles.cardMeta}>
                        <span>{passing} passing</span>
                        <span>{share}%</span>
                      </span>
                    </button>
                  );
                })}
              </div>

              <div className={styles.tools}>
                <h6 className={styles.title}>{selected?.spec?.compliance?.title ?? selected?.getName()}</h6>
                <Chips
                  options={[
                    { id: "failing", label: "Failing" },
                    { id: "all", label: "All controls" },
                  ]}
                  selected={new Set([onlyFailing ? "failing" : "all"])}
                  onToggle={(id) => setOnlyFailing(id === "failing")}
                />
                <span className={styles.updated}>
                  {selected?.status?.updateTimestamp ? `updated ${formatAge(selected.status.updateTimestamp)} ago` : ""}
                </span>
                <input
                  className={styles.search}
                  type="search"
                  placeholder="Search Controls"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </div>

              {rows.length === 0 ? (
                <Muted>{onlyFailing ? "No failing controls." : "No controls match."}</Muted>
              ) : (
                <Table scrollable={false} sortSyncWithUrl={false} className={styles.table}>
                  <TableHead flat sticky={false}>
                    <TableCell className={styles.id}>Control</TableCell>
                    <TableCell className={styles.name}>Name</TableCell>
                    <TableCell className={styles.severity}>Severity</TableCell>
                    <TableCell className={styles.count}>Failing</TableCell>
                  </TableHead>
                  {rows.map((row) => (
                    <TableRow key={row.id} nowrap>
                      <TableCell className={styles.id}>{row.id}</TableCell>
                      <TableCell className={styles.name}>
                        <WithTooltip tooltip={controls.get(row.id)?.description}>{row.name}</WithTooltip>
                      </TableCell>
                      <TableCell className={styles.severity}>
                        <SeverityLabel severity={row.severity} />
                      </TableCell>
                      <TableCell className={styles.count}>
                        <SeverityCount severity="critical" count={row.totalFail ?? 0} />
                      </TableCell>
                    </TableRow>
                  ))}
                </Table>
              )}
            </>
          )}
        </div>
      </TabLayout>
    );
  }),
);
