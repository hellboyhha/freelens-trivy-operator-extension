// A store the way the host's list selection sees it: observable items and selection, and a `remove`
// that deletes an item, as the host's does.

import { observable, runInAction } from "mobx";
import { vi } from "vitest";

export function selectableStore<T extends { getId(): string }>(objects: T[]) {
  const items = observable.array(objects, { deep: false });
  const selected = observable.set<string>();
  const store = {
    isLoaded: true,
    failedLoading: false,
    loadAll: async () => {},
    items,
    get contextItems() {
      return items;
    },
    selectedItemsIds: selected,
    get selectedItems() {
      return items.filter((i) => selected.has(i.getId()));
    },
    isSelected: (i: T) => selected.has(i.getId()),
    toggleSelection: (i: T) =>
      runInAction(() => (selected.has(i.getId()) ? selected.delete(i.getId()) : selected.add(i.getId()))),
    resetSelection: () => runInAction(() => selected.clear()),
    pickOnlySelected: (list: T[]) => list.filter((i) => selected.has(i.getId())),
    getTotalCount: () => items.length,
    remove: vi.fn(async (i: T) => {
      runInAction(() => {
        items.remove(i);
        selected.delete(i.getId());
      });
    }),
  };
  return store;
}
