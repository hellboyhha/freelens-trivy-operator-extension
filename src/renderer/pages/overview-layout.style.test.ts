// The Overview stacks Fix first above Compliance and starts with the same header bar Freelens draws on its
// own pages (measured in Freelens 1.10: --contentColor background, 16px padding on every side, 64px high,
// title in --textColorPrimary). These read the stylesheet, so a side-by-side grid or an off-theme bar
// cannot come back unnoticed.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const scss = readFileSync(fileURLToPath(new URL("overview-page.module.scss", import.meta.url)), "utf8")
  .replace(/\/\*[\s\S]*?\*\//g, "")
  .replace(/\/\/.*$/gm, "");

const rule = (selector: string) => new RegExp(`(?:^|\\n)\\s*\\.${selector}\\s*\\{([^}]*)\\}`).exec(scss)?.[1] ?? "";

describe("Overview layout", () => {
  it("stacks Fix first and Compliance, never side by side", () => {
    const stack = rule("columns") || rule("stack");
    expect(stack).not.toBe("");
    expect(stack).not.toMatch(/grid-template-columns/);
    expect(stack).toMatch(/flex-direction:\s*column/);
    expect(scss).not.toMatch(/@media/);
  });

  it("sits flush in the page like the host's, with its 16px gap between blocks", () => {
    const page = rule("overview");
    expect(page).not.toMatch(/padding/);
    expect(page).toMatch(/gap:\s*calc\(\$unit \* 2\)/);
  });

  it("draws the header bar like the Freelens page header", () => {
    const header = rule("header");
    expect(header).toMatch(/background:\s*var\(--contentColor\)/);
    expect(header).toMatch(/padding:\s*calc\(\$unit \* 2\)/);
    expect(header).toMatch(/min-height:\s*calc\(\$unit \* 8\)/);
    expect(header).toMatch(/justify-content:\s*space-between/);
    // Freelens: `.WorkloadsOverview .header h5 { color: var(--textColorPrimary) }`
    expect(rule("title")).toMatch(/color:\s*var\(--textColorPrimary\)/);
  });

  it("sizes the Compliance table columns so the numbers sit under their headers", () => {
    expect(scss).toMatch(/&\.benchmarkName/);
    expect(scss).toMatch(/&\.passFail/);
    expect(scss).toMatch(/&\.progress/);
  });

  it("lets the progress bar fill its cell (a bar in a flex cell is 0px wide unless it grows)", () => {
    const progress = /&\.progress\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/.exec(scss)?.[1] ?? "";
    expect(progress).toMatch(/>\s*\*\s*\{[^}]*flex:\s*1/);
  });
});
