// One factory builds every report list, so they share layout, sorting, search and filters.

import { Renderer } from "@freelensapp/extensions";
import * as MobxReact from "mobx-react";
import React from "react";
import { maybe } from "../../common/utils";
import { matchPackages } from "../api/trivy/report-model";
import { withErrorPage } from "./error-page";
import { ExportMenu } from "./export-menu";
import { applyFilters, chipOptions, type FilterSpec, toggleFilter, visibleSelection } from "./filters";
import styles from "./report-list.module.scss";
import stylesInline from "./report-list.module.scss?inline";
import { RescanPill, RescanStyles, RescanToolbarButton, useRescan, useRescanTracker } from "./rescan-ui";
import { SeverityStyles } from "./severity-count";
import { Chips, Muted, UiStyles } from "./ui";

import type { RemovableStore } from "../api/trivy/rescan";
import type { Column, ListContext, ReportObject } from "./report-columns";

const { observer } = MobxReact;

const {
  Component: { KubeObjectListLayout, SearchInput },
} = Renderer;

export interface ReportListOptions<T extends ReportObject> {
  tableId: string;
  title: string;
  /** The kind, such as `SbomReport`; the host's Search box is worded from it. */
  kind: string;
  /** The kind's store; the page is only mounted once the CRD is known to exist. */
  getStore: () => unknown;
  columns: Column<T>[];
  /** Column to sort by when the page opens, worst first for severities. */
  defaultSort: string;
  /** Chips above the table. */
  filters?: FilterSpec<T>[];
  /** Adds a box to find a package by name, version or purl in each report's components (SBOM lists). */
  packageSearch?: boolean;
  /** Filter ids that are on when the page opens. */
  defaultFilters?: string[];
  /**
   * Whether Rescan is offered. True by default. SBOM lists set it false: the operator does not
   * regenerate an SBOM report that is deleted, so deleting one would only make it vanish.
   */
  rescan?: boolean;
}

/** What the list reads from the host's store, besides what every list needs. */
interface ListStore<T> {
  contextItems?: T[];
  items?: T[];
  selectedItems?: T[];
  resetSelection?: () => void;
}

export interface ReportListProps {
  extension: Renderer.LensExtension;
  /** Shown at the right of the chips row, such as the namespaced / cluster-scoped switch. */
  aside?: React.ReactNode;
}

/** `SbomReport` as `Sbom Report`: a kind name in words. */
function spaceWords(kind: string): string {
  return kind.replace(/([a-z0-9])([A-Z])/g, "$1 $2");
}

export function createReportListPage<T extends ReportObject>(options: ReportListOptions<T>) {
  const { columns, filters = [] } = options;
  const extraSearch = columns.flatMap((c) => (c.search ? [c.search] : []));

  return observer((props: ReportListProps) =>
    withErrorPage(props, () => {
      const [query, setQuery] = React.useState("");
      // The reports the table shows right now: after the host's namespace and search filters and ours.
      const exported = React.useRef<T[]>([]);
      const [, refresh] = React.useReducer((n: number) => n + 1, 0);
      const [selected, setSelected] = React.useState<ReadonlySet<string>>(new Set(options.defaultFilters ?? []));

      // The host can drop and re-register a kind's store while a page is open (the cluster's
      // CRDs are re-read); until it is back the page waits instead of failing.
      const store = maybe(() => options.getStore()) as ListStore<T> | null;
      const loaded = store?.items ?? store?.contextItems ?? [];
      const { waiting, ghosts: allGhosts, now } = useRescanTracker<T>(options.kind, loaded);
      const rescan = useRescan<T>(() => store as RemovableStore<T>, { after: () => store?.resetSelection?.() });
      if (!store) return <p style={{ padding: 16 }}>Waiting for the {options.title} store...</p>;

      // A wait is only shown while the report would be: not for a namespace the filter has hidden.
      const filterNamespaces = maybe(() => Renderer.K8sApi.namespaceStore.contextNamespaces) ?? [];
      const ghosts = allGhosts.filter(
        (g) =>
          filterNamespaces.length === 0 || !g.metadata.namespace || filterNamespaces.includes(g.metadata.namespace),
      );
      const isGhost = (o: T) => ghosts.includes(o);

      // The chips and switch sit above the layout, not in its `info` slot: the host puts that slot
      // inside the one-line header row, where anything wide pushes the whole table sideways.
      const total = store.contextItems?.length ?? 0;
      const context: ListContext = { query: options.packageSearch ? query : "" };
      const searching = context.query.trim().length > 0;
      const byPackage = (items: T[]) =>
        searching
          ? items.filter((o) => matchPackages(o.report?.components?.components, context.query).length > 0)
          : items;
      const visibleItems = byPackage(applyFilters(store.contextItems ?? [], filters, selected));
      const shown = visibleItems.length;
      // What the toolbar acts on: the ticked reports that are on screen right now, after the host's
      // namespace and search filters and ours. Waiting rows are never in it.
      // Reading `selectedItems` here is what re-draws the toolbar when a row is ticked.
      const ticked = new Set<T>(store.selectedItems ?? []);
      const chosen = exported.current.filter((o) => ticked.has(o));
      const chipsOn = searching || filters.some((f) => selected.has(f.id));
      const searchPlaceholder = `Search ${spaceWords(options.kind)}`;
      // The host's own search box, so it is the same design as the Search box beside it. Its global
      // Cmd/Ctrl+F hotkey stays with the host's box.
      const packageBox = options.packageSearch ? (
        <SearchInput
          placeholder="Find a package"
          value={query}
          showClearIcon
          bindGlobalFocusHotkey={false}
          onChange={(value: string) => setQuery(value)}
        />
      ) : null;
      const visible = columns.filter((c) => !c.when || c.when(context));
      const sortingCallbacks = Object.fromEntries(
        visible
          .filter((c) => c.sort)
          .map((c) => [c.id, (o: T) => (c.sort as NonNullable<Column<T>["sort"]>)(o, context)]),
      );
      const renderTableHeader = visible.map((c) => ({
        title: c.title,
        className: c.className,
        sortBy: c.sort ? c.id : undefined,
      }));
      const noun = total === 1 ? "report" : "reports";
      const rescanning = ghosts.length > 0 ? ` · ${ghosts.length} rescanning` : "";
      const countText = (chipsOn ? `${shown} of ${total} ${noun}` : `${total} ${noun}`) + rescanning;

      const above = (
        <div className={styles.above}>
          <div className={styles.toolbar}>
            <div className={styles.chipsAndCount}>
              {filters.length > 0 ? (
                <Chips
                  flush
                  options={chipOptions(filters)}
                  selected={visibleSelection(filters, selected)}
                  onToggle={(id) => setSelected(toggleFilter(filters, selected, id))}
                />
              ) : null}
              <span className={styles.count} data-testid="count">
                {countText}
                {chosen.length > 0 ? (
                  <>
                    {" · "}
                    <b>{chosen.length} selected</b>{" "}
                    <button type="button" className={styles.clear} onClick={() => store.resetSelection?.()}>
                      Clear
                    </button>
                  </>
                ) : null}
              </span>
            </div>
            <div className={styles.tools}>
              {options.rescan !== false ? (
                <RescanToolbarButton count={chosen.length} onClick={() => rescan.ask(chosen)} />
              ) : null}
              <ExportMenu title={options.title} items={chosen} />
              {props.aside}
            </div>
          </div>
        </div>
      );

      return (
        <div className={styles.listRoot}>
          <style>{stylesInline}</style>
          <UiStyles />
          <SeverityStyles />
          <RescanStyles />
          {above}
          {rescan.dialog}
          <div className={styles.listBody}>
            <KubeObjectListLayout<T, any>
              tableId={options.tableId}
              className={styles.page}
              store={store as any}
              sortingCallbacks={sortingCallbacks as any}
              searchFilters={[(o: T) => o.getSearchFields(), ...extraSearch]}
              filterItems={[
                (items: T[]) => {
                  const shownNow = byPackage(applyFilters([...items, ...ghosts], filters, selected));
                  const rows = shownNow.filter((o) => !isGhost(o));
                  const changed =
                    rows.length !== exported.current.length || rows.some((o, i) => o !== exported.current[i]);
                  exported.current = rows;
                  // The toolbar is drawn before the table, so it learns of a new set of rows one beat later.
                  if (changed) queueMicrotask(refresh);
                  return shownNow;
                },
              ]}
              // The host's round "remove" button deletes selected reports behind a generic prompt; Rescan
              // above is the one deliberate way to delete, so that button goes.
              addRemoveButtons={{ onRemove: undefined }}
              // A row waiting for its new report has nothing to open.
              customizeTableRowProps={(o: T) => (isGhost(o) ? { onClick: () => {}, selected: false } : {})}
              // The page and the toolbar already say what this is and how many there are, so the host's
              // title and "N items" go; the empty info panel keeps the filter and search at the right.
              customizeHeader={(placeholders) => ({
                ...placeholders,
                title: null,
                info: <span />,
                // The package box sits right before the host's Search box.
                filters: (
                  <>
                    {placeholders.filters}
                    {packageBox}
                  </>
                ),
                searchProps: { ...placeholders.searchProps, placeholder: searchPlaceholder },
              })}
              renderHeaderTitle=""
              // The host's virtual list gives every row a fixed 32px; two-line cells need the row to grow.
              virtual={false}
              renderTableHeader={renderTableHeader}
              renderTableContents={(o: T) => {
                const wait = isGhost(o) ? waiting.find((p) => p.item === o) : undefined;
                if (!wait) {
                  return visible.map((c) => <React.Fragment key={c.id}>{c.render(o, context)}</React.Fragment>);
                }
                // The workload and image stay; the first other column says what is happening.
                const status = visible.find((c) => c.id !== "workload" && c.id !== "image");
                return visible.map((c) => (
                  <React.Fragment key={c.id}>
                    {c.id === "workload" || c.id === "image" ? (
                      c.render(o, context)
                    ) : c === status ? (
                      <RescanPill pending={wait} now={now} />
                    ) : (
                      <Muted>–</Muted>
                    )}
                  </React.Fragment>
                ));
              }}
              tableProps={{ sortByDefault: { sortBy: options.defaultSort, orderBy: "desc" } }}
            />
          </div>
        </div>
      );
    }),
  );
}
