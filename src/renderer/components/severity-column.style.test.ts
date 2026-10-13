// The severity column must be wide enough for everything the cell can hold, or the cell's last part
// ("+103 unknown") runs into the next column.
//
// Measured in Freelens 1.10 at the host's 14px: the widest cell is the bar (140px) + 12px gap + four
// numbers + "+103 unknown", which needs 349px, plus the cell's own 8px of padding on each side.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const NEEDED = 349 + 16;

const read = (path: string) =>
  readFileSync(fileURLToPath(new URL(path, import.meta.url)), "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/.*$/gm, "");

const minWidth = (scss: string, selector: string) => {
  const body = new RegExp(`&\\.${selector}\\s*\\{([^}]*)\\}`).exec(scss)?.[1] ?? "";
  return Number(/min-width:\s*(\d+)px/.exec(body)?.[1] ?? 0);
};

describe("severity column width", () => {
  it("fits the bar, the four numbers and the unknown count on the list pages", () => {
    expect(minWidth(read("report-list.module.scss"), "severityCell")).toBeGreaterThanOrEqual(NEEDED);
  });

  it("fits the same cell in the Overview's Fix first table", () => {
    expect(minWidth(read("../pages/overview-page.module.scss"), "severity")).toBeGreaterThanOrEqual(NEEDED);
  });
});
