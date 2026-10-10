// Minimal stub of the host-provided `@freelensapp/extensions` module.
//
// At runtime Freelens injects this module as the `global.LensExtensions`
// global, so it is never bundled (see `globalExternals` in
// `electron.vite.config.js`) and cannot be imported in a plain Node/vitest
// process - the real package pulls in Electron. Unit tests alias the import to
// this file instead (see the `alias` option in `vitest.config.ts`).
//
// Only the surface actually exercised by the tests is stubbed here. Extend it
// as your tests need more of the host API.
import React from "react";
import { vi } from "vitest";

/** Stores a test hands to `Kind.getStore()`; a kind with none behaves like a missing CRD. */
export const testStores = new Map<unknown, unknown>();

class LensExtensionKubeObject {
  apiVersion?: string;
  kind?: string;
  metadata: any;
  spec?: unknown;
  status?: unknown;

  constructor(data: Record<string, unknown> = {}) {
    Object.assign(this, data);
  }

  static getStore() {
    if (!testStores.has(this)) throw new Error("no store: the CRD is not installed");
    return testStores.get(this);
  }

  getName(): string {
    return this.metadata.name;
  }

  getNs(): string | undefined {
    return this.metadata.namespace || undefined;
  }

  getId(): string {
    return this.metadata.uid;
  }

  getCreationTimestamp(): string {
    return this.metadata.creationTimestamp;
  }

  getSearchFields(): string[] {
    return [this.metadata.name];
  }

  get selfLink(): string {
    return `/apis/aquasecurity.github.io/v1alpha1/${this.metadata.namespace ?? "-"}/${this.metadata.name}`;
  }
}

class LensExtension {
  name = "@hellboyhha/freelens-trivy-operator-extension";
}

// Components are looked up at module load and rendered by the host. Any name resolves to a
// component that renders its label and children, so pages and drawers can be rendered in tests.
const passthrough = ({ name, children }: { name?: string; children?: React.ReactNode }) =>
  React.createElement("div", null, name ? React.createElement("span", null, name) : null, children);
// The list layout also calls the page's cell renderers, so a test sees the rows a user would.
const listLayout = (props: any) =>
  React.createElement(
    "div",
    {
      "data-virtual": String(props.virtual),
      "data-sort": props.tableProps?.sortByDefault?.sortBy,
      // The host adds a round "remove" button for selected items unless the page overrides it.
      "data-host-remove": String(!(props.addRemoveButtons && "onRemove" in props.addRemoveButtons)),
    },
    // The host header as the page leaves it: title, info, the filters slot and the search box.
    (() => {
      const header = props.customizeHeader?.({
        title: "host title",
        info: "host info",
        filters: React.createElement("span", null, "host filters"),
        searchProps: { placeholder: "Search SbomReport..." },
      });
      return React.createElement(
        "div",
        { "data-testid": "host-header" },
        header?.title,
        header?.info,
        header?.filters,
        React.createElement("input", { "data-testid": "host-search", placeholder: header?.searchProps?.placeholder }),
      );
    })(),
    React.createElement(
      "div",
      { "data-testid": "header" },
      ...props.renderTableHeader.map((h: any, i: number) =>
        React.createElement("span", { key: i, "data-class": h.className ?? "" }, h.title),
      ),
    ),
    ...(props.filterItems ?? [])
      .reduce((items: any[], filter: any) => filter(items), props.store.contextItems)
      .map((item: any, i: number) =>
        React.createElement(
          "div",
          {
            key: i,
            "data-testid": "row",
            "data-row-click-overridden": String(typeof props.customizeTableRowProps?.(item)?.onClick === "function"),
          },
          React.createElement("input", {
            type: "checkbox",
            "data-testid": "select",
            checked: props.store.isSelected?.(item) ?? false,
            onChange: () => props.store.toggleSelection?.(item),
          }),
          ...props
            .renderTableContents(item)
            .map((cell: any, j: number) => React.createElement("span", { key: j, "data-testid": "cell" }, cell)),
        ),
      ),
  );
// The host's search box: an input that reports its text, as the real one does.
const searchInput = (props: any) =>
  React.createElement("input", {
    "data-testid": "host-search-input",
    "data-host-component": "SearchInput",
    placeholder: props.placeholder,
    value: props.value ?? "",
    onChange: (e: any) => props.onChange?.(e.target.value, e),
  });
const components = new Proxy(
  {},
  {
    get: (_, name) =>
      name === "KubeObjectListLayout" ? listLayout : name === "SearchInput" ? searchInput : passthrough,
  },
);

/** Notifications the page raised, as the host would show them. */
export const notifications = { ok: vi.fn(), error: vi.fn(), info: vi.fn(), shortInfo: vi.fn() };

/** What the cluster's scan Jobs and pods answer; tests set `jobs` and `pods`, or `fail` to refuse. */
export const scanApi = { jobs: [] as unknown[], pods: [] as unknown[], fail: false };
const listFrom = (key: "jobs" | "pods") => async () => {
  if (scanApi.fail) throw new Error("forbidden");
  return scanApi[key];
};

/** The cluster open in the window; tests change `name`. */
export const activeCluster = { name: "test-cluster" };

export const Renderer = {
  LensExtension,
  Component: new Proxy(components, {
    get: (target: any, name) => (name === "Notifications" ? notifications : target[name]),
  }),
  Catalog: {
    catalogEntities: {
      get activeEntity() {
        return activeCluster.name ? { getName: () => activeCluster.name } : undefined;
      },
    },
  },
  Navigation: { getDetailsUrl: (selfLink: string) => selfLink, hideDetails: vi.fn() },
  K8sApi: {
    LensExtensionKubeObject,
    KubeApi: class KubeApi {},
    KubeObjectStore: class KubeObjectStore {},
    namespaceStore: { contextNamespaces: [] as string[], clearSelected: vi.fn() },
    jobApi: { list: listFrom("jobs") },
    podsApi: { list: listFrom("pods") },
  },
};

export const Common = {
  logger: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
};
