import { describe, expect, it } from "vitest";
import { ALL_CHIP, applyFilters, chipOptions, type FilterSpec, toggleFilter, visibleSelection } from "./filters";

const specs: FilterSpec<number>[] = [
  { id: "big", label: "Big", group: "size", predicate: (n) => n > 10 },
  { id: "huge", label: "Huge", group: "size", predicate: (n) => n > 100 },
  { id: "even", label: "Even", predicate: (n) => n % 2 === 0 },
];

describe("filter chips", () => {
  it("lists All first, then the exclusive group, then the toggles", () => {
    expect(chipOptions(specs).map((o) => o.id)).toEqual([ALL_CHIP, "big", "huge", "even"]);
  });
  it("has no All chip when nothing is exclusive", () => {
    expect(chipOptions([specs[2]]).map((o) => o.id)).toEqual(["even"]);
  });
  it("shows All as on while no grouped chip is chosen", () => {
    expect([...visibleSelection(specs, new Set())]).toEqual([ALL_CHIP]);
    expect(visibleSelection(specs, new Set(["big"])).has(ALL_CHIP)).toBe(false);
    expect(visibleSelection(specs, new Set(["even"])).has(ALL_CHIP)).toBe(true);
  });
  it("keeps one chip per group, lets it be turned off, and All clears the group only", () => {
    let on = toggleFilter(specs, new Set(), "big");
    on = toggleFilter(specs, on, "huge");
    expect([...on]).toEqual(["huge"]);
    on = toggleFilter(specs, on, "even");
    expect(new Set(toggleFilter(specs, on, ALL_CHIP))).toEqual(new Set(["even"]));
    expect([...toggleFilter(specs, new Set(["huge"]), "huge")]).toEqual([]);
  });
  it("ignores an unknown id", () => {
    expect([...toggleFilter(specs, new Set(), "nope")]).toEqual([]);
  });
  it("applies every chip that is on, and nothing when none is", () => {
    const items = [5, 12, 13, 200, 250];
    expect(applyFilters(items, specs, new Set())).toEqual(items);
    expect(applyFilters(items, specs, new Set(["big"]))).toEqual([12, 13, 200, 250]);
    expect(applyFilters(items, specs, new Set(["big", "even"]))).toEqual([12, 200, 250]);
  });
});
