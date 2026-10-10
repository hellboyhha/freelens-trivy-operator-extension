// Loads and watches the stores a page reads that no list layout loads for it.
//
// A KubeObjectListLayout loads its own store. The Overview and the drawer sections read
// stores directly, and a store nobody loaded stays empty without any error. The hook asks
// each store to load for the namespaces in the host's namespace filter, keeps what other
// pages already loaded (`merge`), reports a failed load in the console, and watches the
// store while the component is mounted.

import { Renderer } from "@freelensapp/extensions";
import React from "react";
import { maybe } from "../../common/utils";

export interface LoadableStore {
  isLoaded: boolean;
  failedLoading?: boolean;
  loadAll(options?: {
    namespaces?: string[];
    merge?: boolean;
    onLoadFailure?: (error: unknown) => void;
  }): Promise<unknown>;
  subscribe?(): () => void;
}

export interface StoreRequest {
  label: string;
  store: LoadableStore | null | undefined;
  /** Explicit namespaces; omit to follow the host's namespace filter. */
  namespaces?: string[];
}

export function useLoadedStores(requests: StoreRequest[]): void {
  const latest = React.useRef(requests);
  latest.current = requests;

  const followsFilter = requests.some((request) => !request.namespaces);
  const filterKey = followsFilter
    ? (maybe(() => Renderer.K8sApi.namespaceStore.contextNamespaces.join(",")) ?? "")
    : "";
  const requestKey = requests
    .map((r) => `${r.label}:${r.store ? "y" : "n"}:${(r.namespaces ?? []).join(",")}`)
    .join("|");

  React.useEffect(() => {
    let mounted = true;
    const disposers: (() => void)[] = [];

    for (const { label, store, namespaces } of latest.current) {
      if (!store) continue;
      void (async () => {
        let failure: unknown;
        try {
          await store.loadAll({ namespaces, merge: true, onLoadFailure: (error) => (failure ??= error) });
        } catch (error) {
          failure ??= error;
        }
        if (failure) console.warn(`[trivy-operator-extension] could not load ${label}: ${String(failure)}`);
        if (!mounted || failure) return;
        const dispose = maybe(() => store.subscribe?.());
        if (dispose) disposers.push(dispose);
      })();
    }

    return () => {
      mounted = false;
      for (const dispose of disposers) maybe(dispose);
    };
  }, [filterKey, requestKey]);
}
