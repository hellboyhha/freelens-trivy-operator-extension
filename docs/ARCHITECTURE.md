# Architecture

The extension reads the twelve report kinds of `aquasecurity.github.io/v1alpha1` and presents them as
pages and drawer sections. It targets the Freelens 1.x extension API (React 17, MobX 6, CommonJS output).
The host provides React, MobX and the extension API at runtime, so none are bundled.

## Layers

```
src/
  common/            helpers with no host dependency
  main/              main-process entry (empty: nothing runs outside the window)
  renderer/
    api/trivy/       one KubeObject class per CRD, shared types, pure helpers (report-model.ts)
    components/      list factory, columns, filters, shared UI pieces, pure models
    details/         drawer sections for report kinds and for workloads
    pages/           Overview, report lists, Compliance
    index.tsx        registers pages, sidebar entries and drawer sections
```

`tools/architecture.mjs` enforces the direction: `main`, `renderer` and `common` must not reach into each
other the wrong way, KubeObject classes are static-only, each CRD class declares its required statics, and
every page is rendered through an error boundary.

## Report kinds

Twelve kinds: vulnerability, config audit, exposed secret, RBAC assessment, infra assessment and SBOM, each
with a cluster-scoped twin where the operator has one, plus the cluster compliance report. The data sits in
`.report`, except for compliance, which uses `spec` and `status`. A report links to its workload through the
labels `trivy-operator.resource.{kind,name,namespace}` and `trivy-operator.container.name`.

Pure logic (counts, grouping by package, version order, package matching, severity weights) lives in
`api/trivy/report-model.ts` and `components/overview-model.ts` and is tested without the host.

## Pages

- **List factory** (`components/report-list.tsx`): every report list is built from column definitions
  (`report-columns.tsx`), filter chips (`filters.ts`) and an optional package search. It puts chips and the
  scope switch above the host list, replaces the host header's title and item count with one toolbar row,
  and turns off the host's virtual list so two-line rows fit.
- **Overview**: reads several stores directly (`use-loaded-stores.ts` loads them for the namespace filter),
  says "Not available" for kinds it cannot read, and does not load SBOMs.
- **SBOM**: loads nothing until the user asks; the package search indexes each report's components once.
- **Drawers**: each report kind adds a section to the host drawer; workload kinds add a Trivy Operator section
  that matches reports to the workload (a Deployment through its ReplicaSets, a CronJob through its Jobs).

## Rescan, scan status and export

| File | Role |
|---|---|
| `api/trivy/rescan.ts` | The only cluster write: deletes reports through the host store and classifies the error |
| `api/trivy/rescan-model.ts` | Pure: what is confirmed, what is said afterwards, how a wait ends |
| `api/trivy/rescan-tracker.ts` | Module-level list of waiting reports; polls the scan Jobs while anything waits |
| `api/trivy/scan-activity.ts` | Read-only list of the operator's Jobs and pods (label selector) |
| `api/trivy/scan-status-model.ts` | Pure: turns Jobs and pods into Queued / Starting / Scanning / Failed, and explains failures |
| `api/trivy/export-model.ts` | Pure: CSV and JSON of a list |
| `components/rescan-ui.tsx`, `rescan-action.tsx`, `export-menu.tsx` | The toolbar Rescan button, dialog, row pill, drawer button and Export menu |

`tools/architecture.mjs` fails the build for a cluster write outside `rescan.ts`.

## Things learned about the host

- The host renders a cluster page with no props, so the extension is handed in at registration.
- The host's list layout puts its `info` slot inside a one-line header row; wide content there widens the
  page. Banners and chips go above the layout.
- The virtual list fixes rows at about 32 px.
- Paragraph margins are reset, so spacing is set with flex gaps.
- `Kind.getStore()` throws when the CRD is absent and can disappear while a page is open.
- Colours come from the host's theme variables so light and dark both work.
