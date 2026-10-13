// The four severity columns (Critical, High, Medium, Low) must be wide enough for their header at the host's
// 14px semibold and, on the sortable list pages, for the sort arrow Freelens draws over the cell's right 34px.
// "Medium" is the widest header (about 60px). Header and numbers share the padding, so they keep one right edge.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const read = (path: string) =>
  readFileSync(fileURLToPath(new URL(path, import.meta.url)), "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/.*$/gm, "");

const rule = (scss: string, selector: string) => new RegExp(`&\\.${selector}\\s*\\{([^}]*)\\}`).exec(scss)?.[1] ?? "";
const px = (body: string, property: string) => Number(new RegExp(`${property}:\\s*(\\d+)px`).exec(body)?.[1] ?? 0);

const HEADER = 60;
const CELL_PADDING = 8;

describe("severity columns", () => {
  const list = rule(read("report-list.module.scss"), "severityNumber");

  it("leave room on the list pages for the header and the sort arrow", () => {
    expect(list).not.toBe("");
    expect(px(list, "padding-right")).toBeGreaterThanOrEqual(34);
    expect(px(list, "min-width")).toBeGreaterThanOrEqual(HEADER + px(list, "padding-right") + CELL_PADDING);
    expect(list).toMatch(/justify-content:\s*flex-end/);
    expect(list).toMatch(/text-align:\s*right/);
  });

  it("fit the header in the Overview's Fix first table, which has no sort arrow", () => {
    const overview = rule(read("../pages/overview-page.module.scss"), "severityNumber");
    expect(overview).not.toBe("");
    expect(px(overview, "min-width")).toBeGreaterThanOrEqual(HEADER + 2 * CELL_PADDING);
    expect(overview).toMatch(/justify-content:\s*flex-end/);
    expect(overview).toMatch(/text-align:\s*right/);
  });

  it("have no bar and no unknown label left in the cell", () => {
    const ui = read("ui.module.scss");
    expect(ui).not.toMatch(/\.sevUnknown|\.sevCell|\.sevNumbers/);
  });
});
