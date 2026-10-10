// The Export drop-down must float over the list.
//
// This is a plain check of the stylesheet, because the failure it guards against is invisible in a unit
// test that only looks at the rendered elements: the menu still appears, but with `position: static` it
// sits in the flow and pushes the search row and the table down by its own height. That happened once,
// when a patch to this file swallowed the rule, and it shipped in the first release.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const scss = readFileSync(fileURLToPath(new URL("./export-menu.module.scss", import.meta.url)), "utf8");

/** The body of a top-level rule, found by counting braces so nested rules do not cut it short. */
function ruleBody(selector: string): string {
  const marker = `\n${selector} {`;
  const at = scss.indexOf(marker);
  if (at === -1) return "";
  let depth = 1;
  let body = "";
  for (let i = at + marker.length; i < scss.length; i++) {
    const character = scss[i];
    if (character === "{") depth++;
    if (character === "}") {
      depth--;
      if (depth === 0) break;
    }
    body += character;
  }
  return body;
}

describe("the Export drop-down's stylesheet", () => {
  it("keeps the menu out of the page flow, so opening it cannot move anything", () => {
    const menu = ruleBody(".menu");
    expect(menu, ".menu rule is missing or empty").not.toBe("");
    expect(menu).toContain("position: absolute");
  });

  it("hangs the menu off its own button", () => {
    expect(ruleBody(".root")).toContain("position: relative");
    expect(ruleBody(".menu")).toContain("top: calc(100% + 4px)");
    expect(ruleBody(".menu")).toContain("right: 0");
  });

  it("draws the menu above the list", () => {
    expect(ruleBody(".menu")).toContain("z-index");
    expect(ruleBody(".menu")).toContain("min-width");
  });
});
