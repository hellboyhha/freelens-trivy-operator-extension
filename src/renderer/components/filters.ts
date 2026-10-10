// The filter chips above a list: pure state handling, so it is testable without the host.
//
// A spec with a `group` is exclusive inside it (Critical, High): at most one is on, and the
// "All" chip means none is. A spec without a group is a toggle that stands alone.

import type { ChipOption } from "./ui";

export interface FilterSpec<T> {
  id: string;
  label: string;
  group?: string;
  predicate: (item: T) => boolean;
}

export const ALL_CHIP = "__all";

export function chipOptions<T>(specs: FilterSpec<T>[]): ChipOption[] {
  const grouped = specs.filter((s) => s.group);
  const toggles = specs.filter((s) => !s.group);
  return [
    ...(grouped.length ? [{ id: ALL_CHIP, label: "All" }] : []),
    ...grouped.map(({ id, label }) => ({ id, label })),
    ...toggles.map(({ id, label }) => ({ id, label })),
  ];
}

/** The ids shown as on: the chosen ones, plus "All" while no grouped chip is chosen. */
export function visibleSelection<T>(specs: FilterSpec<T>[], selected: ReadonlySet<string>): Set<string> {
  const on = new Set(selected);
  if (specs.some((s) => s.group) && !specs.some((s) => s.group && selected.has(s.id))) on.add(ALL_CHIP);
  return on;
}

export function toggleFilter<T>(specs: FilterSpec<T>[], selected: ReadonlySet<string>, id: string): Set<string> {
  const next = new Set(selected);
  const spec = specs.find((s) => s.id === id);
  if (id === ALL_CHIP) {
    for (const s of specs) if (s.group) next.delete(s.id);
    return next;
  }
  if (!spec) return next;
  if (next.has(id)) {
    next.delete(id);
    return next;
  }
  if (spec.group) for (const s of specs) if (s.group === spec.group) next.delete(s.id);
  next.add(id);
  return next;
}

export function applyFilters<T>(items: T[], specs: FilterSpec<T>[], selected: ReadonlySet<string>): T[] {
  const active = specs.filter((s) => selected.has(s.id));
  return active.length ? items.filter((item) => active.every((s) => s.predicate(item))) : items;
}
